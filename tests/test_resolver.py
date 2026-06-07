import unittest
from dnslib import DNSRecord, QTYPE, TXT, A, AAAA
from main import Resolver
from utils.ip_utils import is_valid_ipv4, is_valid_ipv6, subnet_mask_from_prefix, int_to_ip
from utils.cidr_utils import calculate_usable_ips


class DummyHandler:
    def __init__(self, client_ip="127.0.0.1", client_port=12345):
        self.client_address = (client_ip, client_port)


class TestResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = Resolver()
        self.handler = DummyHandler()

    def test_cidr_resolution(self):
        # /24 subnet has 254 usable IPs
        request = DNSRecord.question("24.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata).strip('"'), "254")

        # /32 subnet has 1 usable IP
        request = DNSRecord.question("32.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata).strip('"'), "1")

    def test_subnet_mask_resolution(self):
        # /24 subnet mask is 255.255.255.0
        request = DNSRecord.question("24.mask.cidr", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "255.255.255.0")

    def test_time_resolution(self):
        # TXT record returns current time format
        request = DNSRecord.question("time", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertTrue(len(str(reply.rr[0].rdata)) > 0)

        # A record returns time-based IP
        request = DNSRecord.question("time", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        ip_str = str(reply.rr[0].rdata)
        self.assertTrue(ip_str.startswith("127.0.0."))

    def test_client_ip_resolution(self):
        # A record returns client's IPv4
        handler = DummyHandler("192.168.1.50", 54321)
        request = DNSRecord.question("myip", "A")
        reply = self.resolver.resolve(request, handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "192.168.1.50")

        # AAAA record returns client's IPv6
        handler_v6 = DummyHandler("2001:db8::1", 54321)
        request = DNSRecord.question("myip", "AAAA")
        reply = self.resolver.resolve(request, handler_v6)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "2001:db8::1")

    def test_base64_encode_decode(self):
        # Encode "hello"
        request = DNSRecord.question("b64.hello", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata).strip('"'), "aGVsbG8=")

        # Decode "aGVsbG8="
        request = DNSRecord.question("d64.aGVsbG8=", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata).strip('"'), "hello")


class TestUtilities(unittest.TestCase):
    def test_is_valid_ipv4(self):
        self.assertTrue(is_valid_ipv4("127.0.0.1"))
        self.assertTrue(is_valid_ipv4("8.8.8.8"))
        self.assertFalse(is_valid_ipv4("256.0.0.1"))
        self.assertFalse(is_valid_ipv4("abc"))

    def test_is_valid_ipv6(self):
        self.assertTrue(is_valid_ipv6("::1"))
        self.assertTrue(is_valid_ipv6("2001:db8::1"))
        self.assertFalse(is_valid_ipv6("127.0.0.1"))
        self.assertFalse(is_valid_ipv6("g::1"))

    def test_subnet_mask_from_prefix(self):
        self.assertEqual(subnet_mask_from_prefix(24), "255.255.255.0")
        self.assertEqual(subnet_mask_from_prefix(8), "255.0.0.0")
        self.assertEqual(subnet_mask_from_prefix(32), "255.255.255.255")
        self.assertEqual(subnet_mask_from_prefix(0), "0.0.0.0")
        with self.assertRaises(ValueError):
            subnet_mask_from_prefix(-1)
        with self.assertRaises(ValueError):
            subnet_mask_from_prefix(33)

    def test_int_to_ip(self):
        self.assertEqual(int_to_ip(0x7f000001), "127.0.0.1")
        self.assertEqual(int_to_ip(0xffffffff), "255.255.255.255")
        # Test fallback / invalid input behavior
        self.assertEqual(int_to_ip(-1), "255.255.255.255")

    def test_calculate_usable_ips(self):
        self.assertEqual(calculate_usable_ips(24), 254)
        self.assertEqual(calculate_usable_ips(30), 2)
        self.assertEqual(calculate_usable_ips(31), 2)
        self.assertEqual(calculate_usable_ips(32), 1)
        self.assertEqual(calculate_usable_ips(8), 16777214)


if __name__ == "__main__":
    unittest.main()
