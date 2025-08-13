import datetime
import time
import os
import base64
import random
from dnslib import DNSRecord, RR, A, TXT, QTYPE, AAAA
import requests
import ipaddress
from dnslib.server import DNSServer, BaseResolver


class Resolver(BaseResolver):
    """
    Minimal DNS Resolver with only essential features:
      - cidr:      e.g., 24.cidr → usable IPs (TXT)
      - mask.cidr: e.g., 24.mask.cidr → subnet mask (A)
      - time:      time.local → current time
      - ip:        ip.local → server's public IP
    """

    # Domains we respond to
    CIDR_DOMAIN = "cidr"              # Base domain for CIDR queries
    TIME_DOMAINS = {"time"}           # Domains for time queries
    IP_DOMAINS = {"ip"}               # Domains for IP queries
    MYIP_DOMAINS = {"myip"}           # Domains for client IP queries
    BASE64_PREFIX = "b64"             # Prefix for base64 encoding: b64.<text>
    BASE64_DECODE_PREFIX = "d64"      # Prefix for base64 decoding: d64.<base64>
    EXCUSE_DOMAINS = {"excuse"}       # Domain for developer excuses
    PTR_SUFFIXES = ("in-addr.arpa", "ip6.arpa")  # Reverse DNS suffixes

    def __init__(self):
        self._cached_ipv4 = None
        self._cached_ipv6 = None
        self._cache_time = 0
        self._cache_ttl = 300  # Cache for 5 minutes

    def resolve(self, request, handler):
        """
        Main resolver method that parses incoming DNS queries and routes them to appropriate handlers.
        
        Args:
            request: DNS request object from dnslib
            handler: DNS handler object containing client info
            
        Returns:
            DNS reply object or empty reply for unknown queries
        """
        # Extract the query name and type
        qname_str, qtype = self._extract_query(request)
        client_ip = handler.client_address[0]  # Get client's IP address
        print(f"Query from {client_ip}: {qname_str} (type={QTYPE[qtype]})")

        # === 1. Handle: X.cidr → usable IPs (TXT only) ===
        # Match queries like "24.cidr" where X is a number
        if len(qname_str.split(".")) == 2 and qname_str.endswith(f".{self.CIDR_DOMAIN}"):
            prefix_part = qname_str.split(".")[0]
            try:
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    return self._resolve_cidr(request, qtype, prefix)
            except ValueError:
                pass  # Not a valid number, ignore

        # === 2. Handle: X.mask.cidr → subnet mask (A only) ===
        # Match queries like "24.mask.cidr"
        if len(qname_str.split(".")) == 3 and qname_str.endswith(f".mask.{self.CIDR_DOMAIN}"):
            prefix_part = qname_str.split(".")[0]
            try:
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    return self._resolve_subnet_mask(request, qtype, prefix)
            except ValueError:
                pass  # Not a valid number, ignore

        # === 3. Handle: time.local → current time ===
        # Match time-related domains
        if qname_str in self.TIME_DOMAINS:
            return self._resolve_time(request, qtype)

        # === 4. Handle: ip.local → server's public IP ===
        # Match IP-related domains
        if qname_str in self.IP_DOMAINS:
            return self._resolve_server_ip(request, qtype)
            
        # === 5. Handle: myip.local → client's IP ===
        # Match client IP domains
        if qname_str in self.MYIP_DOMAINS:
            return self._resolve_client_ip(request, qtype, handler)
            
        # === 6. Handle: b64.<text> → base64 encode ===
        # Match queries like "b64.hello" to encode text
        parts = qname_str.split('.')
        if len(parts) > 1 and parts[0] == self.BASE64_PREFIX:
            payload = ".".join(parts[1:])
            return self._resolve_b64_encode(request, qtype, payload)

        # === 7. Handle: d64.<base64-chunks> → base64 decode ===
        # Match queries like "d64.aGVsbG8" to decode base64
        if len(parts) > 1 and parts[0] == self.BASE64_DECODE_PREFIX:
            payload = "".join(parts[1:])
            return self._resolve_b64_decode(request, qtype, payload)

        # === 8. Handle: Reverse-IP PTR   *.in-addr.arpa / *.ip6.arpa ===
        # Match reverse DNS queries like "1.2.3.4.in-addr.arpa"
        # if qname_str.endswith(self.PTR_SUFFIXES):
        #     return self._resolve_ptr(request, qtype, qname_str)

        # Unknown query → return empty reply
        return request.reply()

    def _extract_query(self, request):
        """
        Extract the lowercase domain name and query type from the DNS request.
        
        Args:
            request: DNS request object
            
        Returns:
            Tuple of (query_name, query_type)
        """
        qname = str(request.q.qname).strip(".").lower()
        qtype = request.q.qtype
        return qname, qtype

    def _resolve_cidr(self, request, qtype, prefix):
        """
        Respond to CIDR queries with usable IP count.
        
        Args:
            request: DNS request object
            qtype: Query type (A or TXT)
            prefix: CIDR prefix (0-32)
            
        Returns:
            DNS reply with usable IP count
        """
        reply = request.reply()
        qname = request.q.qname

        # Calculate total hosts in subnet: 2^(32-prefix)
        total_hosts = 1 << (32 - prefix)
        
        # Special cases: /31 (2 usable), /32 (1 host)
        usable = 2 if prefix == 31 else (1 if prefix == 32 else max(0, total_hosts - 2))

        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(str(usable))))
        return reply

    def _resolve_subnet_mask(self, request, qtype, prefix):
        """
        Respond to subnet mask queries with subnet mask value.
        
        Args:
            request: DNS request object
            qtype: Query type (A only)
            prefix: CIDR prefix (0-32)
            
        Returns:
            DNS reply with subnet mask
        """
        reply = request.reply()
        qname = request.q.qname
        mask = self._subnet_mask_from_prefix(prefix)

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(mask)))
        return reply

    def _resolve_time(self, request, qtype):
        """
        Respond to time queries with current local time.
        
        Args:
            request: DNS request object
            qtype: Query type (TXT or A)
            
        Returns:
            DNS reply with current time
        """
        reply = request.reply()
        qname = request.q.qname
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(current_time)))
        elif qtype == QTYPE.A:
            # Return a fake IP based on current second
            sec = datetime.datetime.now().second % 255 + 1
            fake_ip = f"127.0.0.{sec}"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip)))
        return reply

    def _resolve_server_ip(self, request, qtype):
        """
        Respond to IP queries with server's public IP address.
        
        Args:
            request: DNS request object
            qtype: Query type (A, AAAA, or TXT)
            
        Returns:
            DNS reply with server's IP address
        """
        reply = request.reply()
        qname = request.q.qname

        # Get cached or fetch new IP addresses
        ipv4_address, ipv6_address = self._get_public_ips()

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ipv4_address)))
        elif qtype == QTYPE.AAAA:
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(ipv6_address)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"IPv4: {ipv4_address}, IPv6: {ipv6_address}")))
        elif qtype == QTYPE.ANY:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ipv4_address)))
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(ipv6_address)))
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"IPv4: {ipv4_address}, IPv6: {ipv6_address}")))
        return reply

    def _get_public_ips(self):
        """
        Get public IPv4 and IPv6 addresses with caching.
        
        Returns:
            Tuple of (ipv4_address, ipv6_address)
        """
        current_time = time.time()
        
        # Check if cache is still valid
        if (current_time - self._cache_time) < self._cache_ttl and self._cached_ipv4 and self._cached_ipv6:
            return self._cached_ipv4, self._cached_ipv6
        
        # Fetch new IP addresses
        ipv4_address = self._fetch_ipv4()
        ipv6_address = self._fetch_ipv6()
        
        # Update cache
        self._cached_ipv4 = ipv4_address
        self._cached_ipv6 = ipv6_address
        self._cache_time = current_time
        
        return ipv4_address, ipv6_address

    def _fetch_ipv4(self):
        """Fetch public IPv4 address."""
        services = [
            "https://ipv4.icanhazip.com",
            "https://api.ipify.org",
            "https://v4.ident.me",
            "https://ipecho.net/plain"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                ip = response.text.strip()
                if self._is_valid_ipv4(ip):
                    return ip
            except Exception:
                continue
        
        return "127.0.0.1"  # Fallback

    def _fetch_ipv6(self):
        """Fetch public IPv6 address."""
        services = [
            "https://ipv6.icanhazip.com",
            "https://v6.ident.me"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                ip = response.text.strip()
                if self._is_valid_ipv6(ip):
                    return ip
            except Exception:
                continue
        
        return "::1"  # Fallback

    def _resolve_client_ip(self, request, qtype, handler):
        """
        Respond to client IP queries with the client's IP address.
        
        Args:
            request: DNS request object
            qtype: Query type (A, AAAA, or TXT)
            handler: DNS handler containing client information
            
        Returns:
            DNS reply with client's IP address
        """
        reply = request.reply()
        qname = request.q.qname
        client_ip = handler.client_address[0]

        # Determine if client_ip is IPv4 or IPv6
        is_ipv4 = self._is_valid_ipv4(client_ip)
        is_ipv6 = self._is_valid_ipv6(client_ip)

        if qtype == QTYPE.A and is_ipv4:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(client_ip)))
        elif qtype == QTYPE.AAAA and is_ipv6:
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(client_ip)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(client_ip)))
        return reply

    def _subnet_mask_from_prefix(self, prefix):
        """
        Convert CIDR prefix to subnet mask (e.g., 24 → 255.255.255.0).
        
        Args:
            prefix: CIDR prefix (0-32)
            
        Returns:
            Subnet mask as dotted decimal string
        """
        if prefix == 0:
            return "0.0.0.0"
        bits = 0xFFFFFFFF << (32 - prefix)
        return self._int_to_ip(bits)

    def _int_to_ip(self, x):
        """
        Convert a 32-bit integer to IPv4 string.
        
        Args:
            x: 32-bit integer
            
        Returns:
            IPv4 address as string
        """
        return ".".join(str((x >> i) & 0xFF) for i in (24, 16, 8, 0))

    def _is_valid_ipv4(self, ip: str) -> bool:
        """
        Check if a string is a valid IPv4 address.
        
        Args:
            ip: IP address string
            
        Returns:
            Boolean indicating validity
        """
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    def _is_valid_ipv6(self, ip: str) -> bool:
        """
        Check if a string is a valid IPv6 address.

        Args:
            ip: IP address string

        Returns:
            Boolean indicating validity
        """
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ipaddress.AddressValueError:
            return False

    # Helper for Base-64 encoding
    def _resolve_b64_encode(self, request, qtype, text: str):
        """
        Encode text to base64 and return as TXT response.
        
        Args:
            request: DNS request object
            qtype: Query type (TXT only)
            text: Text to encode
            
        Returns:
            DNS reply with base64 encoded text
        """
        reply = request.reply()
        if qtype == QTYPE.TXT:
            encoded = base64.b64encode(text.encode()).decode()
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(encoded)))
        return reply

    # Helper for Base-64 decoding
    def _resolve_b64_decode(self, request, qtype, encoded_text: str):
        """
        Decode base64 text and return as TXT response.
        
        Args:
            request: DNS request object
            qtype: Query type (TXT only)
            encoded_text: Base64 encoded text to decode
            
        Returns:
            DNS reply with decoded text or error message
        """
        reply = request.reply()
        if qtype == QTYPE.TXT:
            try:
                decoded = base64.b64decode(encoded_text).decode('utf-8')
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(decoded)))
            except Exception:
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT("Invalid base64")))
        return reply

    # Helper for PTR
    # def _resolve_ptr(self, request, qtype, qname_str: str):
    #     """
    #     Handle reverse DNS (PTR) queries.
        
    #     Args:
    #         request: DNS request object
    #         qtype: Query type (PTR only)
    #         qname_str: Full query name
            
    #     Returns:
    #         DNS reply with PTR record or empty reply for malformed queries
    #     """
    #     parts = qname_str.split(".")
    #     suffix = ".".join(parts[-2:])          # in-addr.arpa OR ip6.arpa
    #     prefix = parts[:-2]                    # the IP labels, reversed

    #     if suffix == "in-addr.arpa" and len(prefix) == 4:
    #         # Handle IPv4 reverse DNS: 1.2.3.4.in-addr.arpa → 1.2.3.4
    #         ip = ".".join(reversed(prefix))    # 4.3.2.1 -> 1.2.3.4
    #         hostname = f"{ip}.you.example.net."
    #     elif suffix == "ip6.arpa" and len(prefix) == 32:
    #         # Handle IPv6 reverse DNS
    #         # collapse nibbles to full IPv6 address
    #         nibbles = reversed(prefix)
    #         ip6 = ":".join([
    #             "".join(nibbles[i:i+4])
    #             for i in range(0, 32, 4)
    #         ])
    #         hostname = f"{ip6}.you.example.net."
    #     else:
    #         return request.reply()             # malformed → empty

    #     reply = request.reply()
    #     if qtype == QTYPE.PTR:
    #         reply.add_answer(RR(request.q.qname, QTYPE.PTR,
    #                             rdata=DNSRecord.parse(hostname).q.qname))
    #     return reply


def main():
    """
    Start the DNS server on localhost:20000.
    """
    resolver = Resolver()
    server = DNSServer(resolver, port=20000, address='localhost')
    print("DNS Server running on localhost:20000")
    print("Supported queries:")
    print("  dig @localhost -p 20000 24.cidr TXT        -> usable IPs")
    print("  dig @localhost -p 20000 24.mask.cidr A     -> subnet mask")
    print("  dig @localhost -p 20000 time TXT           -> current time")
    print("  dig @localhost -p 20000 ip A               -> server's public IPv4 & IPv6")
    print("  dig @localhost -p 20000 myip A             -> your client IP (A/AAAA/TXT)")
    print("  dig @localhost -p 20000 b64.hello TXT        -> base64 encode 'hello'")
    print("  dig @localhost -p 20000 d64.aGVsbG8 TXT      -> base64 decode 'aGVsbG8'")

    try:
        server.start_thread()
        print("Server started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()


if __name__ == '__main__':
    main()