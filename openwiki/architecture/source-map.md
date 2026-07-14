---
type: "Architecture"
title: "Source Map"
description: "File-by-file reference mapping repository structure to functionality"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["architecture", "source-map", "reference"]
---

## Repository Structure

```
dnspython/
├── main.py                      # Main DNS server entrypoint + Resolver class
├── Dockerfile                   # Multi-stage Docker build
├── docker-compose.yml           # Docker Compose config
├── pyproject.toml               # Project metadata (Python 3.13+)
├── requirements.txt             # Pinned dependencies (requests==2.28.0)
├── uv.lock                      # uv lockfile
├── README.md                    # Project documentation
├── AGENTS.md                    # Agent instructions
├── CLAUDE.md                    # Claude-specific instructions
├── .dockerignore                # Docker ignore patterns
├── .gitignore                   # Git ignore patterns
├── data/                        # (empty) data directory
├── scripts/                     # (empty) scripts directory
├── tests/
│   └── test_resolver.py         # Comprehensive test suite
├── utils/
│   ├── __init__.py              # Package init
│   ├── base64_utils.py          # Base64 encode/decode utilities
│   ├── cidr_utils.py            # CIDR calculation utilities
│   ├── ip_fetch_utils.py        # Public IP fetching with fallbacks
│   ├── ip_utils.py              # IP validation, subnet mask, int↔IP conversion
│   └── time_utils.py            # Time formatting utilities
└── openwiki/                    # Generated documentation (this wiki)
```

---

## File-by-File Reference

### `main.py` — Main Entry Point & Resolver

**Purpose**: DNS server startup, Resolver class with rule-based routing

**Key Components**:

| Component | Type | Purpose |
|-----------|------|---------|
| `QueryContext` | `@dataclass` | Immutable query context (request, qtype, qname, client info, parsed parts) |
| `Rule` | `NamedTuple` | Matcher + handler pair: `(name, matcher_fn, handler_fn)` |
| `Resolver` | `class` (extends `BaseResolver`) | Core resolver with rule registry and caching |
| `Resolver.rules` | `List[Rule]` | Ordered rule registry (first match wins) |
| `Resolver.resolve()` | `method` | Main entry: parses query, iterates rules, dispatches |
| `Resolver._get_public_ips()` | `method` | Cached public IP fetch (5-min TTL) |
| `main()` | `function` | Server startup, logging, signal handling |

**Rule Registry** (in order):

| Rule Name | Matcher | Handler | Domains/Patterns |
|-----------|---------|---------|------------------|
| CIDR Usable IPs | `_match_cidr` | `_reply_cidr` | `X.cidr` (TXT) |
| Subnet Mask | `_match_subnet_mask` | `_reply_subnet_mask` | `X.mask.cidr` (A) |
| Time Services | `_match_time` | `_reply_time` | `time` (TXT, A) |
| Server Public IP | `_match_server_ip` | `_reply_server_ip` | `ip` (A, AAAA, TXT) |
| Client IP | `_match_client_ip` | `_reply_client_ip` | `myip` (A, AAAA, TXT) |
| Base64 Encode | `_match_b64_encode` | `_reply_b64_encode` | `b64.<text>` (TXT) |
| Base64 Decode | `_match_b64_decode` | `_reply_b64_decode` | `d64.<data>` (TXT) |
| lower → UPPER | `_match_lower` | `_reply_upper` | `lower.<text>` (TXT) |
| UPPER → lower | `_match_upper_to_lower` | `_reply_lower` | `upper.<text>` (TXT) |
| echo UPPER | `_match_echo_upper` | `_reply_upper` | `up.<text>` (TXT) |

**Helper Methods**:
- `_match_prefix_payload(ctx, prefix)` — Shared prefix matcher for `b64.`, `d64.`, `lower.`, `upper.`, `up.`
- `_reply_txt_transform(ctx, payload, transform)` — Shared TXT response builder

---

### `utils/ip_utils.py` — IP Utilities

| Function | Purpose |
|----------|---------|
| `is_valid_ipv4(ip)` | Validate IPv4 address |
| `is_valid_ipv6(ip)` | Validate IPv6 address |
| `subnet_mask_from_prefix(prefix)` | CIDR prefix → subnet mask (e.g., 24 → 255.255.255.0) |
| `int_to_ip(x)` | 32-bit int → IPv4 string |

---

### `utils/cidr_utils.py` — CIDR Calculations

| Function | Purpose |
|----------|---------|
| `calculate_usable_ips(prefix)` | Usable IPs in /prefix (handles /31, /32 special cases) |

---

### `utils/time_utils.py` — Time Utilities

| Function | Purpose |
|----------|---------|
| `get_current_time()` | Formatted local time: `YYYY-MM-DD HH:MM:SS` |
| `get_current_second()` | Current second (0-59) |

---

### `utils/base64_utils.py` — Base64 Utilities

| Function | Purpose |
|----------|---------|
| `encode_base64(text)` | UTF-8 text → Base64 string |
| `decode_base64(encoded)` | Base64 → UTF-8 text (handles missing padding, returns "Invalid base64" on error) |

---

### `utils/ip_fetch_utils.py` — Public IP Fetching

| Function | Purpose |
|----------|---------|
| `_fetch_ip(services, validator, fallback, label)` | Generic fetcher with fallback chain |
| `fetch_ipv4()` | Fetch public IPv4 (tries icanhazip, ipify, ident.me, ipecho) |
| `fetch_ipv6()` | Fetch public IPv6 (tries icanhazip, ident.me) |

**Fallback behavior**: Returns `127.0.0.1` (IPv4) or `::1` (IPv6) if all services fail

---

### `tests/test_resolver.py` — Test Suite

**Structure**:

| Test Class | Coverage |
|------------|----------|
| `TestIpUtils` | IP validation, subnet mask, int↔IP |
| `TestCidrUtils` | Usable IPs calculation (standard + edge cases /31, /32) |
| `TestBase64Utils` | Encode, decode, roundtrip, unicode, invalid handling |
| `TestTimeUtils` | Time format, second range |
| `TestIpFetchUtils` | IPv4/IPv6 fetch success, fallback, error handling (mocked) |
| `TestResolver` | Full resolver integration (all rule types, qtypes, edge cases) |
| `TestResolverMatchers` | Unit tests for each matcher function |
| `TestResolverReplies` | Unit tests for each reply builder |

**Test Helpers**:
- `DummyHandler` — Mock handler with configurable client address
- `_make_ctx(qname, qtype, client_ip)` — Build QueryContext for unit tests
- `_txt(reply)` — Extract TXT record text from reply

---

### Configuration Files

| File | Purpose |
|------|---------|
| `pyproject.toml` | Project metadata, Python ≥3.13, deps: dnslib, requests |
| `requirements.txt` | Pinned deps: dnspython, dnslib, ipaddress, requests==2.28.0 |
| `Dockerfile` | Multi-stage: builder (uv) → runtime (python:3.12-slim) |
| `docker-compose.yml` | Service `dnspython`, builds `.`, maps port 8000:8000 |
| `.dockerignore` | Excludes .git, __pycache__, .venv, tests, docs, openwiki |
| `.gitignore` | Excludes __pycache__, .venv, .env, *.pyc, dist, build, .pytest_cache |

---

## Adding a New Feature

Per `README.md` → "Adding New Features":

1. **Add utility** in appropriate `utils/` module (or new one)
2. **Add matcher** `_match_<feature>(self, ctx) -> Optional[Dict]` in `Resolver`
3. **Add handler** `_reply_<feature>(self, ctx, **kwargs) -> DNSRecord` in `Resolver`
4. **Register rule** in `Resolver.__init__`: `Rule("Name", self._match_<feature>, self._reply_<feature>)`
5. **Add tests** in `tests/test_resolver.py`
6. **Update README** with query examples