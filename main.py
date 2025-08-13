import datetime
import time
import os

from dnslib import DNSRecord, RR, A, TXT, QTYPE
from dnslib.server import DNSServer, BaseResolver


class Resolver(BaseResolver):
    """
    A DNS resolver that responds with the current local time or server IP.
    """

    LOCAL_TIME_NAMES = {"time.local", "time", "time.localhost"}
    LOCAL_IP_NAMES = {"ip.local", "ip", "ip.localhost"}
    LOCAL_CIDR_NAMES = {"cidr.local", "cidr", "cidr.localhost"}

    LOCAL_IP = "127.0.0.1"

    def resolve(self, request, handler):
        """
        Main resolver method. Responds to DNS queries with the current time or IP.
        """
        qname_str, qtype = self._extract_query(request)
        if qname_str in self.LOCAL_TIME_NAMES:
            return self._resolve_time(request, qtype)
        elif qname_str in self.LOCAL_IP_NAMES:
            return self._resolve_ip(request, qtype)
        else:
            return request.reply()  # Empty reply for unknown names

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
        elif qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(current_time)))
        else:
            reply.add_ar(RR(qname, QTYPE.TXT, rdata=TXT(current_time)))
        return reply

    def _resolve_ip(self, request, qtype):
        reply = request.reply()
        qname = request.q.qname

        ip_address = os.popen("curl ifconfig.me").read().strip()

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_address)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(ip_address)))
        return reply

    def _cidr(self, request, qtype):
        reply = request.reply()
        qname = request.q.qname

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(self.LOCAL_IP)))
        elif qtype == QTYPE.TXT:
            reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(self.LOCAL_IP)))
        return reply

def main():
    resolver = Resolver()
    server = DNSServer(resolver, port=5353, address='localhost')
    server.start_thread()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping server...")
        server.stop()

if __name__ == '__main__':
    main()