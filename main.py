import datetime
import time
import os
import random
from dnslib import DNSRecord, RR, A, TXT, QTYPE
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
    CIDR_DOMAIN = "cidr"
    TIME_DOMAINS = {"time.local", "time"}
    IP_DOMAINS = {"ip.local", "ip"}

    def resolve(self, request, handler):
        """
        Main resolver: parses query and responds based on domain.
        """
        qname_str, qtype = self._extract_query(request)
        client_ip = handler.client_address[0]
        print(f"Query from {client_ip}: {qname_str} (type={QTYPE[qtype]})")

        # === 1. Handle: X.cidr → usable IPs (TXT only) ===
        if len(qname_str.split(".")) == 2 and qname_str.endswith(f".{self.CIDR_DOMAIN}"):
            prefix_part = qname_str.split(".")[0]
            try:
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    return self._resolve_cidr(request, qtype, prefix)
            except ValueError:
                pass

        # === 2. Handle: X.mask.cidr → subnet mask (A only) ===
        if len(qname_str.split(".")) == 3 and qname_str.endswith(f".mask.{self.CIDR_DOMAIN}"):
            prefix_part = qname_str.split(".")[0]
            try:
                prefix = int(prefix_part)
                if 0 <= prefix <= 32:
                    return self._resolve_subnet_mask(request, qtype, prefix)
            except ValueError:
                pass

        # === 3. Handle: time.local → current time ===
        if qname_str in self.TIME_DOMAINS:
            return self._resolve_time(request, qtype)

        # === 4. Handle: ip.local → server's public IP ===
        if qname_str in self.IP_DOMAINS:
            return self._resolve_server_ip(request, qtype)

        # Unknown query → return empty reply
        return request.reply()

    def _extract_query(self, request):
        """
        Extract lowercase domain name (without trailing dot) and query type.
        """
        qname = str(request.q.qname).strip(".").lower()
        qtype = request.q.qtype
        return qname, qtype

    def _resolve_cidr(self, request, qtype, prefix):
        """
        Respond to 'X.cidr' with usable IP count (TXT only).
        """
        reply = request.reply()
        qname = request.q.qname

        total_hosts = 1 << (32 - prefix)
        usable = 2 if prefix == 31 else (1 if prefix == 32 else max(0, total_hosts - 2))

        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(str(usable))))
        return reply

    def _resolve_subnet_mask(self, request, qtype, prefix):
        """
        Respond to 'X.mask.cidr' with subnet mask (A only).
        """
        reply = request.reply()
        qname = request.q.qname
        mask = self._subnet_mask_from_prefix(prefix)

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(mask)))
        return reply

    def _resolve_time(self, request, qtype):
        """
        Respond to 'time.local' with current local time.
        """
        reply = request.reply()
        qname = request.q.qname
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(current_time)))
        elif qtype == QTYPE.A:
            sec = datetime.datetime.now().second % 255 + 1
            fake_ip = f"127.0.0.{sec}"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip)))
        return reply

    def _resolve_server_ip(self, request, qtype):
        """
        Respond to 'ip.local' with the server's public IP address (IPv4 and IPv6).
        """
        reply = request.reply()
        qname = request.q.qname

        # Get IPv4 address
        try:
            ipv4_address = os.popen("curl -s ifconfig.me").read().strip()
            if not ipv4_address or not self._is_valid_ipv4(ipv4_address):
                ipv4_address = "127.0.0.1"
        except Exception:
            ipv4_address = "127.0.0.1"

        # Get IPv6 address
        try:
            ipv6_address = os.popen("curl -s ifconfig.me/ip").read().strip()
            # Basic validation for IPv6
            if ":" not in ipv6_address or len(ipv6_address) < 2:
                ipv6_address = "::1"
        except Exception:
            ipv6_address = "::1"

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(f"{ipv4_address} {ipv6_address}")))
        return reply

    def _subnet_mask_from_prefix(self, prefix):
        """
        Convert CIDR prefix to subnet mask (e.g., 24 → 255.255.255.0).
        """
        if prefix == 0:
            return "0.0.0.0"
        bits = 0xFFFFFFFF << (32 - prefix)
        return self._int_to_ip(bits)

    def _int_to_ip(self, x):
        """
        Convert 32-bit integer to IPv4 string.
        """
        return ".".join(str((x >> i) & 0xFF) for i in (24, 16, 8, 0))

    def _is_valid_ipv4(self, ip):
        """
        Check if string is valid IPv4 address.
        """
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


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
    print("  dig @localhost -p 20000 time.local TXT     -> current time")
    print("  dig @localhost -p 20000 ip.local A         -> server's public IPv4 & IPv6")

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