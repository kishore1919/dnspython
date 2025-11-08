import time
import requests
from dnslib import DNSRecord, RR, A, TXT, QTYPE, AAAA
from dnslib.server import DNSServer, BaseResolver

# Import utility functions
from utils.ip_utils import is_valid_ipv4, is_valid_ipv6, subnet_mask_from_prefix, int_to_ip
from utils.base64_utils import encode_base64, decode_base64
from utils.ip_fetch_utils import fetch_ipv4, fetch_ipv6
from utils.time_utils import get_current_time, get_current_second
from utils.cidr_utils import calculate_usable_ips


class Resolver(BaseResolver):
    """
    Minimal DNS Resolver supporting:
      - 24.cidr           → usable IPs (TXT)
      - 24.mask.cidr      → subnet mask (A)
      - time              → current time (TXT or A)
      - ip                → server's public IPv4/IPv6
      - myip              → client's IP
      - b64.<text>        → Base64 encode
      - d64.<data>        → Base64 decode
    """

    CIDR_DOMAIN = "cidr"
    TIME_DOMAINS = {"time"}
    IP_DOMAINS = {"ip"}
    MYIP_DOMAINS = {"myip"}
    BASE64_ENCODE_PREFIX = "b64"
    BASE64_DECODE_PREFIX = "d64"
    PTR_SUFFIXES = ("in-addr.arpa", "ip6.arpa")

    def __init__(self):
        super().__init__()
        self._cached_ipv4 = None
        self._cached_ipv6 = None
        self._cache_time = 0
        self._cache_ttl = 300  # 5 minutes

    def resolve(self, request, handler):
        """Main DNS resolution logic."""
        # Extract query
        qname = str(request.q.qname).strip(".")
        qtype = request.q.qtype
        qname_lower = qname.lower()
        client_ip, client_port = handler.client_address

        print(f"Query from {client_ip}:{client_port}: {qname_lower} (type={QTYPE[qtype]})")

        parts = qname_lower.split(".")
        original_parts = qname.split(".")  # Preserve case for Base64

        # --- 1. CIDR: X.cidr → usable IPs ---
        if len(parts) == 2 and parts[1] == self.CIDR_DOMAIN:
            try:
                prefix = int(parts[0])
                if 0 <= prefix <= 32:
                    return self._reply_cidr(request, qtype, prefix)
            except ValueError:
                pass

        # --- 2. Subnet Mask: X.mask.cidr → A record ---
        if len(parts) == 3 and parts[1:] == ["mask", self.CIDR_DOMAIN]:
            try:
                prefix = int(parts[0])
                if 0 <= prefix <= 32:
                    return self._reply_subnet_mask(request, qtype, prefix)
            except ValueError:
                pass

        # --- 3. Time ---
        if qname_lower in self.TIME_DOMAINS:
            return self._reply_time(request, qtype)

        # --- 4. Server Public IP ---
        if qname_lower in self.IP_DOMAINS:
            return self._reply_server_ip(request, qtype)

        # --- 5. Client IP ---
        if qname_lower in self.MYIP_DOMAINS:
            return self._reply_client_ip(request, qtype, client_ip)

        # --- 6. Base64 Encode: b64.<text> ---
        if len(parts) > 1 and parts[0] == self.BASE64_ENCODE_PREFIX:
            payload = ".".join(original_parts[1:])  # Preserve case
            return self._reply_b64_encode(request, qtype, payload)

        # --- 7. Base64 Decode: d64.<data> ---
        if len(parts) > 1 and parts[0] == self.BASE64_DECODE_PREFIX:
            payload = ".".join(original_parts[1:])  # Preserve case
            return self._reply_b64_decode(request, qtype, payload)

        # Unknown query
        print("DEBUG: Unknown query, returning empty reply")
        return request.reply()

    # --- Response Builders ---

    def _reply_cidr(self, request, qtype, prefix):
        """Return number of usable IPs for a /prefix."""
        reply = request.reply()
        if qtype == QTYPE.TXT:
            usable = calculate_usable_ips(prefix)
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(str(usable))))
        return reply

    def _reply_subnet_mask(self, request, qtype, prefix):
        """Return subnet mask for a /prefix as A record."""
        reply = request.reply()
        if qtype == QTYPE.A:
            mask = subnet_mask_from_prefix(prefix)
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(mask)))
        return reply

    def _reply_time(self, request, qtype):
        """Return current time as TXT or a fake time-based IP."""
        reply = request.reply()
        if qtype == QTYPE.TXT:
            current_time = get_current_time()
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(current_time)))
        elif qtype == QTYPE.A:
            sec = get_current_second() % 255 + 1
            fake_ip = f"127.0.0.{sec}"
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(fake_ip)))
        return reply

    def _reply_server_ip(self, request, qtype):
        """Return server's public IP (cached)."""
        reply = request.reply()
        ipv4, ipv6 = self._get_public_ips()

        if qtype == QTYPE.A:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ipv4)))
        elif qtype == QTYPE.AAAA:
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(ipv6)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(f"IPv4: {ipv4}, IPv6: {ipv6}")))
        else:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ipv4)))  # Default
        return reply

    def _reply_client_ip(self, request, qtype, client_ip):
        """Return client's IP based on query type."""
        reply = request.reply()
        is_ipv4 = is_valid_ipv4(client_ip)
        is_ipv6 = is_valid_ipv6(client_ip)

        if qtype == QTYPE.A and is_ipv4:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(client_ip)))
        elif qtype == QTYPE.AAAA and is_ipv6:
            reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(client_ip)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(client_ip)))
        else:
            # Default: respond with appropriate type or TXT
            if is_ipv4 and (qtype in (QTYPE.A, 0)):
                reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(client_ip)))
            elif is_ipv6 and (qtype in (QTYPE.AAAA, 0)):
                reply.add_answer(RR(request.q.qname, QTYPE.AAAA, rdata=AAAA(client_ip)))
            else:
                reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(client_ip)))
        return reply

    def _reply_b64_encode(self, request, qtype, text):
        """Return Base64-encoded text."""
        reply = request.reply()
        if qtype == QTYPE.TXT:
            encoded = encode_base64(text)
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(encoded)))
        return reply

    def _reply_b64_decode(self, request, qtype, encoded_text):
        """Return Base64-decoded text."""
        reply = request.reply()
        if qtype == QTYPE.TXT:
            decoded = decode_base64(encoded_text)
            reply.add_answer(RR(request.q.qname, QTYPE.TXT, rdata=TXT(decoded)))
        return reply

    # --- Helpers ---

    def _get_public_ips(self):
        """Fetch and cache public IPv4 and IPv6 addresses."""
        now = time.time()
        if (now - self._cache_time) < self._cache_ttl and self._cached_ipv4 and self._cached_ipv6:
            return self._cached_ipv4, self._cached_ipv6

        print("Fetching fresh public IPs...")
        ipv4 = fetch_ipv4() or "0.0.0.0"
        ipv6 = fetch_ipv6() or "::"

        self._cached_ipv4 = ipv4
        self._cached_ipv6 = ipv6
        self._cache_time = now
        print(f"Cached IPs - IPv4: {ipv4}, IPv6: {ipv6}")

        return ipv4, ipv6


def main():
    """Start the DNS server."""
    resolver = Resolver()
    server = DNSServer(resolver, port=20000, address='localhost')

    print("DNS Server running on localhost:20000")
    print("Supported queries:")
    print("  dig @localhost -p 20000 24.cidr TXT +short       -> usable IPs")
    print("  dig @localhost -p 20000 24.mask.cidr A +short    -> subnet mask")
    print("  dig @localhost -p 20000 time TXT +short          -> current time")
    print("  dig @localhost -p 20000 ip A/AAAA/TXT +short     -> server's public IPs")
    print("  dig @localhost -p 20000 myip A/AAAA/TXT +short   -> your client IP")
    print("  dig @localhost -p 20000 b64.hello TXT +short     -> base64 encode 'hello'")
    print("  dig @localhost -p 20000 d64.aGVsbG8 TXT +short   -> base64 decode 'aGVsbG8'")

    try:
        server.start_thread()
        print("Server started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()


if __name__ == '__main__':
    print("--- DNS Python script starting ---")
    main()