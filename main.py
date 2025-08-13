import datetime
import time
import os

from dnslib import DNSRecord, RR, A, TXT, QTYPE
from dnslib.server import DNSServer, BaseResolver


class Resolver(BaseResolver):
    """
    A DNS resolver that responds with:
    - Current local time for 'time', 'time.localhost'
    - Server's public IP for 'ip', 'ip.localhost'
    - Client's IP for 'cidr', 'cidr.localhost'
    - Usable IP count for '<number>.cidr' (e.g., 8.cidr TXT → 16777214)
    """

    LOCAL_TIME_NAMES = {"time", "time.localhost"}
    LOCAL_IP_NAMES = {"ip", "ip.localhost"}
    CLIENT_CIDR_NAMES = {"cidr", "cidr.localhost"}  # For plain 'cidr' query
    CIDR_DOMAIN = "cidr"  # Base domain for *.cidr

    LOCAL_IP = "127.0.0.1"

    def resolve(self, request, handler):
        qname_str, qtype = self._extract_query(request)
        client_ip = handler.client_address[0]
        print(f"Query from {client_ip}: {qname_str} (type={QTYPE[qtype]})")

        # 1. Handle plain names: time, ip, cidr
        if qname_str in self.LOCAL_TIME_NAMES:
            return self._resolve_time(request, qtype)
        elif qname_str in self.LOCAL_IP_NAMES:
            return self._resolve_ip(request, qtype)
        elif qname_str in self.CLIENT_CIDR_NAMES:
            return self._resolve_client_ip(request, qtype, client_ip)

        # 2. Handle pattern: <number>.cidr  → e.g., 8.cidr
        if qname_str.endswith(f".{self.CIDR_DOMAIN}"):
            prefix_str = qname_str.split(".", 1)[0]
            try:
                prefix = int(prefix_str)
                if 0 <= prefix <= 32:
                    return self._resolve_cidr_block(request, qtype, prefix)
            except ValueError:
                pass  # Not a number

        # Unknown query
        return request.reply()

    def _extract_query(self, request):
        qname = str(request.q.qname).strip(".").lower()
        qtype = request.q.qtype
        return qname, qtype

    def _resolve_time(self, request, qtype):
        reply = request.reply()
        qname = request.q.qname
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(current_time)))
        # Avoid A record with non-IP string; instead return nothing or dummy
        elif qtype == QTYPE.A:
            # Use a dummy IP or omit. We'll return 127.0.0.time_last_two_digits
            sec = datetime.datetime.now().second
            fake_ip = f"127.0.0.{(sec % 255) + 1}"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip)))
        else:
            # Fallback: add as additional record
            reply.add_ar(RR(qname, QTYPE.TXT, rdata=TXT(current_time)))
        return reply

    def _resolve_ip(self, request, qtype):
        reply = request.reply()
        qname = request.q.qname

        try:
            ip_address = os.popen("curl -s ifconfig.me").read().strip()
            if not ip_address or not self._is_valid_ipv4(ip_address):
                ip_address = self.LOCAL_IP
        except Exception:
            ip_address = self.LOCAL_IP

        if qtype == QTYPE.A and self._is_valid_ipv4(ip_address):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_address)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(ip_address)))
        return reply

    def _resolve_client_ip(self, request, qtype, client_ip):
        reply = request.reply()
        qname = request.q.qname

        if qtype == QTYPE.A and self._is_valid_ipv4(client_ip):
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(client_ip)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(client_ip)))
        return reply

    def _resolve_cidr_block(self, request, qtype, prefix):
        """Respond with usable IP count for /prefix network."""
        total_hosts = 1 << (32 - prefix)

        if prefix == 31 or prefix == 32:
            # RFC 3021: /31 has 2 usable IPs (no broadcast/network)
            # /32 is a single host → 1 IP, but often considered 0 usable for subnet
            usable_hosts = 2 if prefix == 31 else 1
        else:
            usable_hosts = max(0, total_hosts)  # normal subnets

        reply = request.reply()
        qname = request.q.qname

        if qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(str(usable_hosts))))
        elif qtype == QTYPE.A:
            fake_ip = f"10.{min(prefix, 255)}.0.1"
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(fake_ip)))
        return reply
    
    def _is_valid_ipv4(self, ip):
        """Check if a string is a valid IPv4 address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False


def main():
    resolver = Resolver()
    server = DNSServer(resolver, port=20000, address='localhost')
    print("Starting DNS server on localhost:20000...")
    try:
        server.start_thread()
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()


if __name__ == '__main__':
    main()