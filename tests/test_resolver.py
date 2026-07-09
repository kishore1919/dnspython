import unittest
from unittest.mock import MagicMock, patch

from dnslib import DNSRecord, QTYPE

from main import QueryContext, Resolver
from utils.base64_utils import decode_base64, encode_base64
from utils.cidr_utils import calculate_usable_ips
from utils.ip_fetch_utils import fetch_ipv4, fetch_ipv6
from utils.ip_utils import int_to_ip, is_valid_ipv4, is_valid_ipv6, subnet_mask_from_prefix
from utils.time_utils import get_current_second, get_current_time


class DummyHandler:
    def __init__(self, client_ip="127.0.0.1", client_port=12345):
        self.client_address = (client_ip, client_port)


def _txt(reply) -> str:
    return str(reply.rr[0].rdata).strip('"')


def _make_ctx(qname: str, qtype: str = "TXT", client_ip: str = "127.0.0.1") -> QueryContext:
    request = DNSRecord.question(qname, qtype)
    qname_str = str(request.q.qname).strip(".")
    return QueryContext(
        request=request,
        qtype=request.q.qtype,
        qname=qname_str,
        qname_lower=qname_str.lower(),
        client_ip=client_ip,
        client_port=12345,
        parts=qname_str.lower().split("."),
        original_parts=qname_str.split("."),
    )


# ---------------------------------------------------------------------------
# Utility unit tests
# ---------------------------------------------------------------------------


class TestIpUtils(unittest.TestCase):
    def test_is_valid_ipv4_accepts_valid(self):
        self.assertTrue(is_valid_ipv4("127.0.0.1"))
        self.assertTrue(is_valid_ipv4("8.8.8.8"))
        self.assertTrue(is_valid_ipv4("0.0.0.0"))
        self.assertTrue(is_valid_ipv4("255.255.255.255"))

    def test_is_valid_ipv4_rejects_invalid(self):
        self.assertFalse(is_valid_ipv4("256.0.0.1"))
        self.assertFalse(is_valid_ipv4("abc"))
        self.assertFalse(is_valid_ipv4("1.2.3"))
        self.assertFalse(is_valid_ipv4("2001:db8::1"))
        self.assertFalse(is_valid_ipv4(""))

    def test_is_valid_ipv6_accepts_valid(self):
        self.assertTrue(is_valid_ipv6("::1"))
        self.assertTrue(is_valid_ipv6("2001:db8::1"))
        self.assertTrue(is_valid_ipv6("fe80::1"))
        self.assertTrue(is_valid_ipv6("::"))

    def test_is_valid_ipv6_rejects_invalid(self):
        self.assertFalse(is_valid_ipv6("127.0.0.1"))
        self.assertFalse(is_valid_ipv6("g::1"))
        self.assertFalse(is_valid_ipv6(""))
        self.assertFalse(is_valid_ipv6("not-an-ip"))

    def test_subnet_mask_from_prefix(self):
        self.assertEqual(subnet_mask_from_prefix(24), "255.255.255.0")
        self.assertEqual(subnet_mask_from_prefix(8), "255.0.0.0")
        self.assertEqual(subnet_mask_from_prefix(16), "255.255.0.0")
        self.assertEqual(subnet_mask_from_prefix(32), "255.255.255.255")
        self.assertEqual(subnet_mask_from_prefix(0), "0.0.0.0")
        self.assertEqual(subnet_mask_from_prefix(30), "255.255.255.252")

    def test_subnet_mask_from_prefix_raises_on_invalid(self):
        with self.assertRaises(ValueError):
            subnet_mask_from_prefix(-1)
        with self.assertRaises(ValueError):
            subnet_mask_from_prefix(33)

    def test_int_to_ip(self):
        self.assertEqual(int_to_ip(0x7F000001), "127.0.0.1")
        self.assertEqual(int_to_ip(0xFFFFFFFF), "255.255.255.255")
        self.assertEqual(int_to_ip(0), "0.0.0.0")
        self.assertEqual(int_to_ip(0x08080808), "8.8.8.8")
        # Out-of-range falls back to bit-shift formatting
        self.assertEqual(int_to_ip(-1), "255.255.255.255")


class TestCidrUtils(unittest.TestCase):
    def test_calculate_usable_ips_standard(self):
        self.assertEqual(calculate_usable_ips(24), 254)
        self.assertEqual(calculate_usable_ips(8), 16777214)
        self.assertEqual(calculate_usable_ips(16), 65534)
        self.assertEqual(calculate_usable_ips(30), 2)
        self.assertEqual(calculate_usable_ips(0), 4294967294)

    def test_calculate_usable_ips_special_cases(self):
        self.assertEqual(calculate_usable_ips(31), 2)
        self.assertEqual(calculate_usable_ips(32), 1)


class TestBase64Utils(unittest.TestCase):
    def test_encode_base64(self):
        self.assertEqual(encode_base64("hello"), "aGVsbG8=")
        self.assertEqual(encode_base64(""), "")
        self.assertEqual(encode_base64("DNS"), "RE5T")

    def test_encode_base64_unicode(self):
        self.assertEqual(encode_base64("café"), "Y2Fmw6k=")

    def test_decode_base64(self):
        self.assertEqual(decode_base64("aGVsbG8="), "hello")
        self.assertEqual(decode_base64("RE5T"), "DNS")

    def test_decode_base64_missing_padding(self):
        # Missing padding should still decode
        self.assertEqual(decode_base64("aGVsbG8"), "hello")

    def test_decode_base64_invalid(self):
        self.assertEqual(decode_base64("!!!not-valid!!!"), "Invalid base64")
        self.assertEqual(decode_base64("===="), "Invalid base64")

    def test_encode_decode_roundtrip(self):
        for text in ("hello", "foo.bar", "x" * 100, "12345"):
            self.assertEqual(decode_base64(encode_base64(text)), text)


class TestTimeUtils(unittest.TestCase):
    def test_get_current_time_format(self):
        value = get_current_time()
        self.assertRegex(value, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

    def test_get_current_second_range(self):
        sec = get_current_second()
        self.assertIsInstance(sec, int)
        self.assertGreaterEqual(sec, 0)
        self.assertLessEqual(sec, 59)


class TestIpFetchUtils(unittest.TestCase):
    @patch("utils.ip_fetch_utils.requests.get")
    def test_fetch_ipv4_success(self, mock_get):
        mock_get.return_value = MagicMock(text="8.8.8.8\n")
        self.assertEqual(fetch_ipv4(), "8.8.8.8")
        mock_get.assert_called()

    @patch("utils.ip_fetch_utils.requests.get")
    def test_fetch_ipv4_skips_invalid_then_succeeds(self, mock_get):
        mock_get.side_effect = [
            MagicMock(text="not-an-ip"),
            MagicMock(text="1.1.1.1"),
        ]
        self.assertEqual(fetch_ipv4(), "1.1.1.1")

    @patch("utils.ip_fetch_utils.requests.get")
    def test_fetch_ipv4_fallback_on_errors(self, mock_get):
        mock_get.side_effect = Exception("network down")
        self.assertEqual(fetch_ipv4(), "127.0.0.1")

    @patch("utils.ip_fetch_utils.requests.get")
    def test_fetch_ipv6_success(self, mock_get):
        mock_get.return_value = MagicMock(text="2001:db8::1\n")
        self.assertEqual(fetch_ipv6(), "2001:db8::1")

    @patch("utils.ip_fetch_utils.requests.get")
    def test_fetch_ipv6_fallback_on_errors(self, mock_get):
        mock_get.side_effect = Exception("network down")
        self.assertEqual(fetch_ipv6(), "::1")


# ---------------------------------------------------------------------------
# Resolver integration / unit tests
# ---------------------------------------------------------------------------


class TestResolver(unittest.TestCase):
    def setUp(self):
        self.resolver = Resolver(cache_ttl=300)
        self.handler = DummyHandler()

    # --- CIDR ---

    def test_cidr_resolution(self):
        request = DNSRecord.question("24.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "254")

        request = DNSRecord.question("32.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "1")

    def test_cidr_wrong_qtype_returns_empty_answers(self):
        request = DNSRecord.question("24.cidr", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    def test_cidr_invalid_prefix_unmatched(self):
        request = DNSRecord.question("33.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

        request = DNSRecord.question("abc.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    # --- Subnet mask ---

    def test_subnet_mask_resolution(self):
        request = DNSRecord.question("24.mask.cidr", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "255.255.255.0")

    def test_subnet_mask_wrong_qtype_returns_empty_answers(self):
        request = DNSRecord.question("24.mask.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    def test_subnet_mask_invalid_prefix_unmatched(self):
        request = DNSRecord.question("99.mask.cidr", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    # --- Time ---

    def test_time_resolution(self):
        request = DNSRecord.question("time", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertRegex(_txt(reply), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

        request = DNSRecord.question("time", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        ip_str = str(reply.rr[0].rdata)
        self.assertTrue(ip_str.startswith("127.0.0."))
        octet = int(ip_str.rsplit(".", 1)[1])
        self.assertGreaterEqual(octet, 1)
        self.assertLessEqual(octet, 60)

    def test_time_unsupported_qtype_returns_empty_answers(self):
        request = DNSRecord.question("time", "AAAA")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    # --- Client IP ---

    def test_client_ip_resolution(self):
        handler = DummyHandler("192.168.1.50", 54321)
        request = DNSRecord.question("myip", "A")
        reply = self.resolver.resolve(request, handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "192.168.1.50")

        handler_v6 = DummyHandler("2001:db8::1", 54321)
        request = DNSRecord.question("myip", "AAAA")
        reply = self.resolver.resolve(request, handler_v6)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "2001:db8::1")

    def test_client_ip_txt(self):
        handler = DummyHandler("10.0.0.5", 1234)
        request = DNSRecord.question("myip", "TXT")
        reply = self.resolver.resolve(request, handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "10.0.0.5")

    def test_client_ip_type_mismatch_falls_back_to_txt(self):
        # IPv4 client asked for AAAA → fallback TXT
        handler = DummyHandler("192.168.1.50", 54321)
        request = DNSRecord.question("myip", "AAAA")
        reply = self.resolver.resolve(request, handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(reply.rr[0].rtype, QTYPE.TXT)
        self.assertEqual(_txt(reply), "192.168.1.50")

    # --- Server public IP ---

    @patch.object(Resolver, "_get_public_ips", return_value=("203.0.113.10", "2001:db8::10"))
    def test_server_ip_a(self, _mock_ips):
        request = DNSRecord.question("ip", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "203.0.113.10")

    @patch.object(Resolver, "_get_public_ips", return_value=("203.0.113.10", "2001:db8::10"))
    def test_server_ip_aaaa(self, _mock_ips):
        request = DNSRecord.question("ip", "AAAA")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "2001:db8::10")

    @patch.object(Resolver, "_get_public_ips", return_value=("203.0.113.10", "2001:db8::10"))
    def test_server_ip_txt(self, _mock_ips):
        request = DNSRecord.question("ip", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertIn("203.0.113.10", _txt(reply))
        self.assertIn("2001:db8::10", _txt(reply))

    # --- Base64 ---

    def test_base64_encode_decode(self):
        request = DNSRecord.question("b64.hello", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "aGVsbG8=")

        request = DNSRecord.question("d64.aGVsbG8=", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "hello")

    def test_base64_encode_wrong_qtype_returns_empty_answers(self):
        request = DNSRecord.question("b64.hello", "A")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    def test_base64_decode_invalid(self):
        request = DNSRecord.question("d64.!!!bad!!!", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "Invalid base64")

    # --- Case conversion ---

    def test_lower_to_upper(self):
        request = DNSRecord.question("lower.hello", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "HELLO")

        request = DNSRecord.question("lower.foo.bar", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "FOO.BAR")

    def test_upper_to_lower(self):
        request = DNSRecord.question("upper.HELLO", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "hello")

        request = DNSRecord.question("upper.FOO.BAR", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "foo.bar")

    def test_up_echo_upper(self):
        request = DNSRecord.question("up.hello", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(_txt(reply), "HELLO")

    def test_case_conversion_wrong_qtype_returns_empty_answers(self):
        for qname in ("lower.hello", "upper.HELLO", "up.hello"):
            request = DNSRecord.question(qname, "A")
            reply = self.resolver.resolve(request, self.handler)
            self.assertEqual(len(reply.rr), 0, msg=qname)

    # --- Unknown / error paths ---

    def test_unknown_query_returns_empty_answers(self):
        request = DNSRecord.question("unknown.domain", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    def test_resolve_handles_handler_exception(self):
        # Force a matched rule's handler to raise
        self.resolver.rules = [
            self.resolver.rules[0]._replace(
                handler=MagicMock(side_effect=RuntimeError("boom"))
            )
        ]
        # Prepend a always-matching rule via patching first matcher
        always = MagicMock(return_value={"prefix": 24})
        self.resolver.rules[0] = self.resolver.rules[0]._replace(matcher=always)

        request = DNSRecord.question("24.cidr", "TXT")
        reply = self.resolver.resolve(request, self.handler)
        self.assertEqual(len(reply.rr), 0)

    def test_resolve_handles_fatal_exception(self):
        bad_handler = MagicMock()
        bad_handler.client_address = None  # unpack will fail
        request = DNSRecord.question("time", "TXT")
        reply = self.resolver.resolve(request, bad_handler)
        self.assertEqual(len(reply.rr), 0)


class TestResolverMatchers(unittest.TestCase):
    def setUp(self):
        self.resolver = Resolver()

    def test_match_cidr(self):
        self.assertEqual(self.resolver._match_cidr(_make_ctx("24.cidr")), {"prefix": 24})
        self.assertEqual(self.resolver._match_cidr(_make_ctx("0.cidr")), {"prefix": 0})
        self.assertIsNone(self.resolver._match_cidr(_make_ctx("33.cidr")))
        self.assertIsNone(self.resolver._match_cidr(_make_ctx("nope")))

    def test_match_subnet_mask(self):
        self.assertEqual(
            self.resolver._match_subnet_mask(_make_ctx("16.mask.cidr")),
            {"prefix": 16},
        )
        self.assertIsNone(self.resolver._match_subnet_mask(_make_ctx("24.cidr")))
        self.assertIsNone(self.resolver._match_subnet_mask(_make_ctx("xx.mask.cidr")))

    def test_match_time(self):
        self.assertEqual(self.resolver._match_time(_make_ctx("time")), {})
        self.assertIsNone(self.resolver._match_time(_make_ctx("nottime")))

    def test_match_server_ip(self):
        self.assertEqual(self.resolver._match_server_ip(_make_ctx("ip")), {})
        self.assertIsNone(self.resolver._match_server_ip(_make_ctx("myip")))

    def test_match_client_ip(self):
        self.assertEqual(self.resolver._match_client_ip(_make_ctx("myip")), {})
        self.assertIsNone(self.resolver._match_client_ip(_make_ctx("ip")))

    def test_match_b64_encode(self):
        self.assertEqual(
            self.resolver._match_b64_encode(_make_ctx("b64.hello.world")),
            {"payload": "hello.world"},
        )
        self.assertIsNone(self.resolver._match_b64_encode(_make_ctx("b64")))

    def test_match_b64_decode(self):
        self.assertEqual(
            self.resolver._match_b64_decode(_make_ctx("d64.aGVsbG8=")),
            {"payload": "aGVsbG8="},
        )
        self.assertIsNone(self.resolver._match_b64_decode(_make_ctx("d64")))

    def test_match_lower(self):
        self.assertEqual(
            self.resolver._match_lower(_make_ctx("lower.hello")),
            {"payload": "hello"},
        )
        self.assertIsNone(self.resolver._match_lower(_make_ctx("lower")))

    def test_match_upper_to_lower(self):
        matched = self.resolver._match_upper_to_lower(_make_ctx("upper.HELLO"))
        self.assertIsNotNone(matched)
        self.assertEqual(matched["payload"].lower(), "hello")
        self.assertIsNone(self.resolver._match_upper_to_lower(_make_ctx("upper")))

    def test_match_echo_upper(self):
        self.assertEqual(
            self.resolver._match_echo_upper(_make_ctx("up.hello")),
            {"payload": "hello"},
        )
        self.assertIsNone(self.resolver._match_echo_upper(_make_ctx("up")))


class TestResolverReplies(unittest.TestCase):
    def setUp(self):
        self.resolver = Resolver()

    def test_reply_cidr(self):
        ctx = _make_ctx("24.cidr", "TXT")
        reply = self.resolver._reply_cidr(ctx, prefix=24)
        self.assertEqual(_txt(reply), "254")

    def test_reply_subnet_mask(self):
        ctx = _make_ctx("24.mask.cidr", "A")
        reply = self.resolver._reply_subnet_mask(ctx, prefix=24)
        self.assertEqual(str(reply.rr[0].rdata), "255.255.255.0")

    def test_reply_time_txt_and_a(self):
        ctx = _make_ctx("time", "TXT")
        reply = self.resolver._reply_time(ctx)
        self.assertRegex(_txt(reply), r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

        ctx = _make_ctx("time", "A")
        reply = self.resolver._reply_time(ctx)
        self.assertTrue(str(reply.rr[0].rdata).startswith("127.0.0."))

    def test_reply_b64_encode_decode(self):
        ctx = _make_ctx("b64.hello", "TXT")
        reply = self.resolver._reply_b64_encode(ctx, payload="hello")
        self.assertEqual(_txt(reply), "aGVsbG8=")

        ctx = _make_ctx("d64.aGVsbG8=", "TXT")
        reply = self.resolver._reply_b64_decode(ctx, payload="aGVsbG8=")
        self.assertEqual(_txt(reply), "hello")

    def test_reply_upper_lower_echo(self):
        ctx = _make_ctx("lower.hello", "TXT")
        reply = self.resolver._reply_upper(ctx, payload="hello")
        self.assertEqual(_txt(reply), "HELLO")

        ctx = _make_ctx("upper.HELLO", "TXT")
        reply = self.resolver._reply_lower(ctx, payload="HELLO")
        self.assertEqual(_txt(reply), "hello")

        ctx = _make_ctx("up.hello", "TXT")
        reply = self.resolver._reply_upper(ctx, payload="hello")
        self.assertEqual(_txt(reply), "HELLO")

    def test_reply_client_ip_txt(self):
        ctx = _make_ctx("myip", "TXT", client_ip="172.16.0.1")
        reply = self.resolver._reply_client_ip(ctx)
        self.assertEqual(_txt(reply), "172.16.0.1")

    def test_reply_server_ip_default_qtype(self):
        ctx = _make_ctx("ip", "MX")
        with patch.object(self.resolver, "_get_public_ips", return_value=("9.9.9.9", "::1")):
            reply = self.resolver._reply_server_ip(ctx)
        self.assertEqual(len(reply.rr), 1)
        self.assertEqual(str(reply.rr[0].rdata), "9.9.9.9")


class TestGetPublicIps(unittest.TestCase):
    def test_get_public_ips_fetches_and_caches(self):
        resolver = Resolver(cache_ttl=60)
        with patch("main.fetch_ipv4", return_value="1.2.3.4") as m4, patch(
            "main.fetch_ipv6", return_value="2001:db8::2"
        ) as m6:
            ipv4, ipv6 = resolver._get_public_ips()
            self.assertEqual((ipv4, ipv6), ("1.2.3.4", "2001:db8::2"))
            self.assertEqual(m4.call_count, 1)
            self.assertEqual(m6.call_count, 1)

            # Second call within TTL uses cache
            ipv4, ipv6 = resolver._get_public_ips()
            self.assertEqual((ipv4, ipv6), ("1.2.3.4", "2001:db8::2"))
            self.assertEqual(m4.call_count, 1)
            self.assertEqual(m6.call_count, 1)

    def test_get_public_ips_refreshes_after_ttl(self):
        resolver = Resolver(cache_ttl=1)
        with patch("main.fetch_ipv4", side_effect=["1.1.1.1", "2.2.2.2"]) as m4, patch(
            "main.fetch_ipv6", side_effect=["::1", "::2"]
        ) as m6, patch("main.time.time", side_effect=[100.0, 102.0]):
            # First fetch at t=100
            self.assertEqual(resolver._get_public_ips(), ("1.1.1.1", "::1"))
            # After TTL at t=102 (cache_time was 100, TTL=1)
            self.assertEqual(resolver._get_public_ips(), ("2.2.2.2", "::2"))
            self.assertEqual(m4.call_count, 2)
            self.assertEqual(m6.call_count, 2)

    def test_get_public_ips_uses_fallback_when_fetch_returns_empty(self):
        resolver = Resolver(cache_ttl=60)
        with patch("main.fetch_ipv4", return_value=""), patch(
            "main.fetch_ipv6", return_value=""
        ):
            ipv4, ipv6 = resolver._get_public_ips()
            self.assertEqual(ipv4, "0.0.0.0")
            self.assertEqual(ipv6, "::")


if __name__ == "__main__":
    unittest.main()
