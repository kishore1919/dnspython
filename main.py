import os
import time
import logging
from typing import Callable, NamedTuple, Optional, Tuple, Dict, Any, List
from dataclasses import dataclass
from dnslib import DNSRecord, RR, A, TXT, QTYPE, AAAA
from dnslib.server import DNSServer, BaseResolver

# Import utility functions
from utils.ip_utils import is_valid_ipv4, is_valid_ipv6, subnet_mask_from_prefix
from utils.base64_utils import encode_base64, decode_base64
from utils.ip_fetch_utils import fetch_ipv4, fetch_ipv6
from utils.time_utils import get_current_time, get_current_second
from utils.cidr_utils import calculate_usable_ips

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("dnspython")


@dataclass
class QueryContext:
    """Context object holding data about the incoming DNS query."""
    request: DNSRecord
    qtype: int
    qname: str
    qname_lower: str
    client_ip: str
    client_port: int
    parts: List[str]
    original_parts: List[str]


class Rule(NamedTuple):
    """A rule mapping a matcher function to a handler function."""
    name: str
    matcher: Callable[[QueryContext], Optional[Dict[str, Any]]]
    handler: Callable[..., DNSRecord]


class Resolver(BaseResolver):
    """
    Minimal DNS Resolver supporting:
      - X.cidr           → usable IPs (TXT)
      - X.mask.cidr      → subnet mask (A)
      - time              → current time (TXT or A)
      - ip                → server's public IPv4/IPv6 (A/AAAA/TXT)
      - myip              → client's IP (A/AAAA/TXT)
      - b64.<text>        → Base64 encode (TXT)
      - d64.<data>        → Base64 decode (TXT)
      - lower.<text>      → lowercase to uppercase (TXT)
      - upper.<text>      → uppercase to lowercase (TXT)
      - up.<text>          → uppercase echo (TXT)
    """

    CIDR_DOMAIN = "cidr"
    TIME_DOMAINS = {"time"}
    IP_DOMAINS = {"ip"}
    MYIP_DOMAINS = {"myip"}
    BASE64_ENCODE_PREFIX = "b64"
    BASE64_DECODE_PREFIX = "d64"
    LOWER_PREFIX = "lower"
    UPPER_TO_LOWER_PREFIX = "upper"
    UPPER_PREFIX = "up"

    def __init__(self, cache_ttl: int = 300):
        super().__init__()
        self._cached_ipv4: Optional[str] = None
        self._cached_ipv6: Optional[str] = None
        self._cache_time: float = 0.0
        self._cache_ttl = cache_ttl

        # Register lookup/routing rules
        self.rules: List[Rule] = [
            Rule("CIDR Usable IPs", self._match_cidr, self._reply_cidr),
            Rule("Subnet Mask", self._match_subnet_mask, self._reply_subnet_mask),
            Rule("Time Services", self._match_time, self._reply_time),
            Rule("Server Public IP", self._match_server_ip, self._reply_server_ip),
            Rule("Client IP", self._match_client_ip, self._reply_client_ip),
            Rule("Base64 Encode", self._match_b64_encode, self._reply_b64_encode),
            Rule("Base64 Decode", self._match_b64_decode, self._reply_b64_decode),
            Rule("lower -> UPPER", self._match_lower, self._reply_upper),
            Rule("UPPER -> lower", self._match_upper_to_lower, self._reply_lower),
            Rule("echo UPPER", self._match_echo_upper, self._reply_upper),
        ]

    def resolve(self, request: DNSRecord, handler: Any) -> DNSRecord:
        """Main DNS resolution logic using registered rules."""
        try:
            qname = str(request.q.qname).strip(".")
            qtype = request.q.qtype
            qname_lower = qname.lower()
            client_ip, client_port = handler.client_address

            logger.info("Query from %s:%d: %s (type=%s)", client_ip, client_port, qname_lower, QTYPE.get(qtype, qtype))

            parts = qname_lower.split(".")
            original_parts = qname.split(".")

            ctx = QueryContext(
                request=request,
                qtype=qtype,
                qname=qname,
                qname_lower=qname_lower,
                client_ip=client_ip,
                client_port=client_port,
                parts=parts,
                original_parts=original_parts,
            )

            for rule in self.rules:
                matched_args = rule.matcher(ctx)
                if matched_args is not None:
                    logger.debug("Matched rule '%s' with args: %s", rule.name, matched_args)
                    try:
                        return rule.handler(ctx, **matched_args)
                    except Exception as e:
                        logger.error("Error executing handler for rule '%s': %s", rule.name, e, exc_info=True)
                        return request.reply()

            logger.debug("Unknown query: %s", qname_lower)
            return request.reply()
        except Exception as e:
            logger.error("Fatal error resolving request: %s", e, exc_info=True)
            return request.reply()

    # --- Matchers ---

    def _match_cidr(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match X.cidr queries."""
        if len(ctx.parts) == 2 and ctx.parts[1] == self.CIDR_DOMAIN:
            try:
                prefix = int(ctx.parts[0])
                if 0 <= prefix <= 32:
                    return {"prefix": prefix}
            except ValueError:
                pass
        return None

    def _match_subnet_mask(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match X.mask.cidr queries."""
        if len(ctx.parts) == 3 and ctx.parts[1:] == ["mask", self.CIDR_DOMAIN]:
            try:
                prefix = int(ctx.parts[0])
                if 0 <= prefix <= 32:
                    return {"prefix": prefix}
            except ValueError:
                pass
        return None

    def _match_time(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match time queries."""
        if ctx.qname_lower in self.TIME_DOMAINS:
            return {}
        return None

    def _match_server_ip(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match ip queries."""
        if ctx.qname_lower in self.IP_DOMAINS:
            return {}
        return None

    def _match_client_ip(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match myip queries."""
        if ctx.qname_lower in self.MYIP_DOMAINS:
            return {}
        return None

    def _match_prefix_payload(self, ctx: QueryContext, prefix: str) -> Optional[Dict[str, Any]]:
        """Match <prefix>.<payload> queries, returning the payload (original case)."""
        if len(ctx.parts) > 1 and ctx.parts[0] == prefix:
            return {"payload": ".".join(ctx.original_parts[1:])}
        return None

    def _match_b64_encode(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match b64.<text> queries."""
        return self._match_prefix_payload(ctx, self.BASE64_ENCODE_PREFIX)

    def _match_b64_decode(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match d64.<data> queries."""
        return self._match_prefix_payload(ctx, self.BASE64_DECODE_PREFIX)

    def _match_lower(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match lower.<text> queries."""
        return self._match_prefix_payload(ctx, self.LOWER_PREFIX)

    def _match_upper_to_lower(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match upper.<text> queries."""
        return self._match_prefix_payload(ctx, self.UPPER_TO_LOWER_PREFIX)

    def _match_echo_upper(self, ctx: QueryContext) -> Optional[Dict[str, Any]]:
        """Match up.<text> queries."""
        return self._match_prefix_payload(ctx, self.UPPER_PREFIX)

    # --- Response Builders ---

    def _reply_cidr(self, ctx: QueryContext, prefix: int) -> DNSRecord:
        """Return number of usable IPs for a /prefix."""
        reply = ctx.request.reply()
        if ctx.qtype == QTYPE.TXT:
            usable = calculate_usable_ips(prefix)
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.TXT, rdata=TXT(str(usable))))
        return reply

    def _reply_subnet_mask(self, ctx: QueryContext, prefix: int) -> DNSRecord:
        """Return subnet mask for a /prefix as A record."""
        reply = ctx.request.reply()
        if ctx.qtype == QTYPE.A:
            mask = subnet_mask_from_prefix(prefix)
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.A, rdata=A(mask)))
        return reply

    def _reply_time(self, ctx: QueryContext) -> DNSRecord:
        """Return current time as TXT or a fake time-based IP."""
        reply = ctx.request.reply()
        if ctx.qtype == QTYPE.TXT:
            current_time = get_current_time()
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.TXT, rdata=TXT(current_time)))
        elif ctx.qtype == QTYPE.A:
            sec = get_current_second() % 255 + 1
            fake_ip = f"127.0.0.{sec}"
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.A, rdata=A(fake_ip)))
        return reply

    def _reply_server_ip(self, ctx: QueryContext) -> DNSRecord:
        """Return server's public IP (cached)."""
        reply = ctx.request.reply()
        ipv4, ipv6 = self._get_public_ips()

        if ctx.qtype == QTYPE.A:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.A, rdata=A(ipv4)))
        elif ctx.qtype == QTYPE.AAAA:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.AAAA, rdata=AAAA(ipv6)))
        elif ctx.qtype == QTYPE.TXT:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.TXT, rdata=TXT(f"IPv4: {ipv4}, IPv6: {ipv6}")))
        else:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.A, rdata=A(ipv4)))  # Default
        return reply

    def _reply_client_ip(self, ctx: QueryContext) -> DNSRecord:
        """Return client's IP based on query type."""
        reply = ctx.request.reply()
        is_ipv4 = is_valid_ipv4(ctx.client_ip)
        is_ipv6 = is_valid_ipv6(ctx.client_ip)

        if ctx.qtype == QTYPE.A and is_ipv4:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.A, rdata=A(ctx.client_ip)))
        elif ctx.qtype == QTYPE.AAAA and is_ipv6:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.AAAA, rdata=AAAA(ctx.client_ip)))
        elif ctx.qtype == QTYPE.TXT:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.TXT, rdata=TXT(ctx.client_ip)))
        else:
            # Type mismatch (e.g. AAAA requested over IPv4): fall back to TXT.
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.TXT, rdata=TXT(ctx.client_ip)))
        return reply

    def _reply_b64_encode(self, ctx: QueryContext, payload: str) -> DNSRecord:
        """Return Base64-encoded text."""
        return self._reply_txt_transform(ctx, payload, encode_base64)

    def _reply_b64_decode(self, ctx: QueryContext, payload: str) -> DNSRecord:
        """Return Base64-decoded text."""
        return self._reply_txt_transform(ctx, payload, decode_base64)

    def _reply_upper(self, ctx: QueryContext, payload: str) -> DNSRecord:
        """Return the query text converted to uppercase."""
        return self._reply_txt_transform(ctx, payload, str.upper)

    def _reply_lower(self, ctx: QueryContext, payload: str) -> DNSRecord:
        """Return the query text converted to lowercase."""
        return self._reply_txt_transform(ctx, payload, str.lower)

    def _reply_txt_transform(self, ctx: QueryContext, payload: str, transform: Callable[[str], str]) -> DNSRecord:
        """Return a TXT record containing transform(payload), for TXT queries only."""
        reply = ctx.request.reply()
        if ctx.qtype == QTYPE.TXT:
            reply.add_answer(RR(ctx.request.q.qname, QTYPE.TXT, rdata=TXT(transform(payload))))
        return reply

    # --- Helpers ---

    def _get_public_ips(self) -> Tuple[str, str]:
        """Fetch and cache public IPv4 and IPv6 addresses."""
        now = time.time()
        if (now - self._cache_time) < self._cache_ttl and self._cached_ipv4 and self._cached_ipv6:
            return self._cached_ipv4, self._cached_ipv6

        logger.info("Fetching fresh public IPs...")
        ipv4 = fetch_ipv4() or "0.0.0.0"
        ipv6 = fetch_ipv6() or "::"

        self._cached_ipv4 = ipv4
        self._cached_ipv6 = ipv6
        self._cache_time = now
        logger.info("Cached IPs - IPv4: %s, IPv6: %s", ipv4, ipv6)

        return ipv4, ipv6


def main() -> None:
    """Start the DNS server."""
    port = int(os.environ.get("DNS_PORT", 20000))
    address = os.environ.get("DNS_ADDRESS", "127.0.0.1")

    resolver = Resolver()
    server = DNSServer(resolver, port=port, address=address)

    logger.info("DNS Server running on %s:%d", address, port)
    examples = [
        ("24.cidr TXT", "usable IPs in /24"),
        ("24.mask.cidr A", "subnet mask for /24"),
        ("time TXT", "current time"),
        ("ip A/AAAA/TXT", "server's public IPs"),
        ("myip A/AAAA/TXT", "your client IP"),
        ("b64.hello TXT", "base64 encode 'hello'"),
        ("d64.aGVsbG8 TXT", "base64 decode 'aGVsbG8'"),
        ("lower.hello TXT", "lowercase -> uppercase 'HELLO'"),
        ("upper.HELLO TXT", "uppercase -> lowercase 'hello'"),
        ("up.hello TXT", "uppercase echo 'HELLO'"),
    ]
    logger.info("Supported queries:")
    for query, desc in examples:
        logger.info("  dig @%s -p %d %-16s -> %s", address, port, query, desc)

    try:
        server.start_thread()
        logger.info("Server started. Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping server...")
        server.stop()


if __name__ == '__main__':
    logger.info("--- DNS Python script starting ---")
    main()