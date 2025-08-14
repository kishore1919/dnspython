import datetime
import time
import random
import requests
from dnslib import DNSRecord, RR, A, TXT, QTYPE, AAAA
from dnslib.server import DNSServer, BaseResolver
from utils.ip_utils import is_valid_ipv4, is_valid_ipv6, subnet_mask_from_prefix, int_to_ip
from utils.base64_utils import encode_base64, decode_base64
from utils.ip_fetch_utils import fetch_ipv4, fetch_ipv6
from utils.time_utils import get_current_time, get_current_second
from utils.cidr_utils import calculate_usable_ips


class Resolver(BaseResolver):
    """
    Minimal DNS Resolver with essential features:
      - cidr:      e.g., 24.cidr → usable IPs (TXT)
      - mask.cidr: e.g., 24.mask.cidr → subnet mask (A)
      - time:      time → current time
      - ip:        ip → server's public IP
      - myip:      myip → client's IP
      - b64/d64:   base64 encode/decode
    """

    # Domains we respond to
    CIDR_DOMAIN = "cidr"              # Base domain for CIDR queries
    TIME_DOMAINS = {"time"}           # Domains for time queries
    IP_DOMAINS = {"ip"}               # Domains for IP queries
    MYIP_DOMAINS = {"myip"}           # Domains for client IP queries
    BASE64_PREFIX = "b64"             # Prefix for base64 encoding: b64.<text>
    BASE64_DECODE_PREFIX = "d64"      # Prefix for base64 decoding: d64.<base64>
    PTR_SUFFIXES = ("in-addr.arpa", "ip6.arpa")  # Reverse DNS suffixes

    def __init__(self):
        self._cached_ipv4 = None
        self._cached_ipv6 = None
        self._cache_time = 0
        self._cache_ttl = 300  # Cache for 5 minutes
        super().__init__()

    def _extract_query(self, request):
        """Extract the domain name and query type from the DNS request."""
        qname = str(request.q.qname).strip(".")
        qtype = request.q.qtype
        return qname, qtype

    def resolve(self, request, handler):
        """
        Main resolver method that parses incoming DNS queries and routes them to appropriate handlers.
        """
        # Extract the query name and type
        qname_str, qtype = self._extract_query(request)
        qname_lower = qname_str.lower()  # Use lowercase for domain matching only
        client_ip, client_port = handler.client_address
        print(f"Query from {client_ip}:{client_port}: {qname_lower} (type={QTYPE[qtype]})")

        # === 1. Handle: X.cidr → usable IPs (TXT only) ===
        if len(qname_lower.split(".")) == 2 and qname_lower.endswith(f".{self.CIDR_DOMAIN}"):
            prefix_part = qname_lower.split(".")[0]
            try:
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    return self._resolve_cidr(request, qtype, prefix)
            except (ValueError, IndexError):
                pass

        # === 2. Handle: X.mask.cidr → subnet mask (A only) ===
        if len(qname_lower.split(".")) == 3 and qname_lower.endswith(f".mask.{self.CIDR_DOMAIN}"):
            prefix_part = qname_lower.split(".")[0]
            try:
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    return self._resolve_subnet_mask(request, qtype, prefix)
            except ValueError:
                pass

        # === 3. Handle: time → current time ===
        if qname_lower in self.TIME_DOMAINS:
            return self._resolve_time(request, qtype)

        # === 4. Handle: ip → server's public IP ===
        if qname_lower in self.IP_DOMAINS:
            return self._resolve_server_ip(request, qtype)

        # === 5. Handle: myip → client's IP ===
        if qname_lower in self.MYIP_DOMAINS:
            return self._resolve_client_ip(request, qtype, client_ip)

        # === 6. Handle: b64.<text> → base64 encode ===
        parts = qname_str.split('.')  # Use original case for base64
        parts_lower = qname_lower.split('.')  # Use lowercase for matching
        if len(parts_lower) > 1 and parts_lower[0] == self.BASE64_PREFIX:
            payload = ".".join(parts[1:])  # Preserve original case
            return self._resolve_b64_encode(request, qtype, payload)

        # === 7. Handle: d64.<base64-chunks> → base64 decode ===
        if len(parts_lower) > 1 and parts_lower[0] == self.BASE64_DECODE_PREFIX:
            payload = ".".join(parts[1:])  # Preserve original case
            return self._resolve_b64_decode(request, qtype, payload)

        # Unknown query → return empty reply
        print(f"DEBUG: Unknown query, returning empty reply")
        return request.reply()

    def _resolve_cidr(self, request, qtype, prefix):
        """Respond to CIDR queries with usable IP count."""
        reply = request.reply()
        qname = request.q.qname
        usable = calculate_usable_ips(prefix)
        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(str(usable))))
        return reply

    def _resolve_subnet_mask(self, request, qtype, prefix):
        """Respond to subnet mask queries with subnet mask value."""
        reply = request.reply()
        qname = request.q.qname
        mask = self._subnet_mask_from_prefix(prefix)
        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(mask)))
        return reply

    def _resolve_time(self, request, qtype):
        """Respond to time queries with current local time."""
        reply = request.reply()
        qname = request.q.qname
        current_time = get_current_time()
        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(current_time)))
        elif qtype == QTYPE.A:
            # Return a fake IP based on current second
            sec = get_current_second() % 255 + 1
            fake_ip = f"127.0.0.{sec}"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip)))
        return reply

    def _resolve_server_ip(self, request, qtype):
        """Respond to IP queries with server's public IP address."""
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
        else:  # Default to A record
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ipv4_address)))
        return reply

    def _get_public_ips(self):
        """
        Get public IPv4 and IPv6 addresses with caching.
        Returns: Tuple of (ipv4_address, ipv6_address)
        """
        current_time = time.time()
        # Check if cache is still valid (5 minutes)
        if (current_time - self._cache_time) < self._cache_ttl and self._cached_ipv4 and self._cached_ipv6:
            return self._cached_ipv4, self._cached_ipv6
        print("Fetching fresh IP addresses...")
        # Fetch new IP addresses
        ipv4_address = self._fetch_ipv4()
        ipv6_address = self._fetch_ipv6()
        # Update cache
        self._cached_ipv4 = ipv4_address
        self._cached_ipv6 = ipv6_address
        self._cache_time = current_time
        print(f"Cached IPs - IPv4: {ipv4_address}, IPv6: {ipv6_address}")
        return ipv4_address, ipv6_address

    def _fetch_ipv4(self):
        """Fetch public IPv4 address."""
        return fetch_ipv4()

    def _fetch_ipv6(self):
        """Fetch public IPv6 address."""
        return fetch_ipv6()

    def _resolve_client_ip(self, request, qtype, client_ip):
        """
        Respond to client IP queries with the client's IP address.
        """
        reply = request.reply()
        qname = request.q.qname
        print(f"Client IP detected: {client_ip}")
        # Determine if client_ip is IPv4 or IPv6
        is_ipv4 = self._is_valid_ipv4(client_ip)
        is_ipv6 = self._is_valid_ipv6(client_ip)
        if qtype == QTYPE.A and is_ipv4:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(client_ip)))
        elif qtype == QTYPE.AAAA and is_ipv6:
            reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(client_ip)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(client_ip)))
        else:
            # Default behavior - return appropriate record type
            if is_ipv4 and (qtype == QTYPE.A or qtype == 0):  # 0 is ANY
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(client_ip)))
            elif is_ipv6 and (qtype == QTYPE.AAAA or qtype == 0):
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(client_ip)))
            else:
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(client_ip)))
        return reply

    def _subnet_mask_from_prefix(self, prefix):
        """Convert CIDR prefix to subnet mask."""
        return subnet_mask_from_prefix(prefix)

    def _int_to_ip(self, x):
        """Convert a 32-bit integer to IPv4 string."""
        return int_to_ip(x)

    def _is_valid_ipv4(self, ip: str) -> bool:
        """Check if a string is a valid IPv4 address."""
        return is_valid_ipv4(ip)

    def _is_valid_ipv6(self, ip: str) -> bool:
        """Check if a string is a valid IPv6 address."""
        return is_valid_ipv6(ip)

    def _resolve_b64_encode(self, request, qtype, text: str):
        """Encode text to base64 and return as TXT response."""
        reply = request.reply()
        if qtype == QTYPE.TXT:
            encoded = encode_base64(text)
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(encoded)))
        return reply

    def _resolve_b64_decode(self, request, qtype, encoded_text: str):
        """Decode base64 text and return as TXT response."""
        reply = request.reply()
        if qtype == QTYPE.TXT:
            decoded = decode_base64(encoded_text)
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(decoded)))
        return reply

def main():
    """Start the DNS server on localhost:20000."""
    resolver = Resolver()
    server = DNSServer(resolver, port=20000, address='localhost')
    print("DNS Server running on localhost:20000")
    print("Supported queries:")
    print("  dig @localhost -p 20000 24.cidr TXT        -> usable IPs")
    print("  dig @localhost -p 20000 24.mask.cidr A     -> subnet mask")
    print("  dig @localhost -p 20000 time TXT           -> current time")
    print("  dig @localhost -p 20000 ip A/AAAA/TXT      -> server's public IPs")
    print("  dig @localhost -p 20000 myip A/AAAA/TXT    -> your client IP")
    print("  dig @localhost -p 20000 b64.hello TXT      -> base64 encode 'hello'")
    print("  dig @localhost -p 20000 d64.aGVsbG8 TXT    -> base64 decode 'aGVsbG8'")

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