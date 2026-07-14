---
type: Architecture
title: Architecture Overview
description: High-level architecture of the DNS Python Server - rule-based resolver, query pipeline, and utility modules.
timestamp: 2025-07-14T16:45:00Z
tags: [architecture, resolver, dns, design]
resource: /main.py
---

# Architecture Overview

## High-Level Structure

```
┌─────────────────────────────────────────────────────────────┐
│                      DNSServer (dnslib)                     │
│                        ┌─────────┐                          │
│                        │Resolver │                          │
│                        └────┬────┘                          │
│                             │                               │
│              ┌──────────────┼──────────────┐                │
│              ▼              ▼              ▼                │
│         ┌─────────┐   ┌───────────┐   ┌──────────┐         │
│         │ Matcher │──▶│  Handler  │   │  Cache   │         │
│         │  Rules  │   │  (Reply)  │   │  (IPs)   │         │
│         └────┬────┘   └─────┬─────┘   └──────────┘         │
│              │              │                               │
│              ▼              ▼                               │
│         ┌──────────────────────────┐                        │
│         │      Utility Modules      │                        │
│         │  cidr, ip, b64, time, ip  │                        │
│         └──────────────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Resolver Pipeline (`main.py:Resolver`)

The resolver uses a **rule-based pipeline** rather than a monolithic `resolve()` method:

```python
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
```

**Flow:**
1. Parse query → `QueryContext`
2. Iterate `self.rules` in order
3. First matching rule's matcher returns `Dict[str, Any]` params
4. Handler builds `DNSRecord` reply with those params
5. Return reply (empty reply = no match = NXDOMAIN-like empty response)

### 2. QueryContext (`main.py:QueryContext`)

Immutable dataclass carrying parsed query data through the pipeline:

```python
@dataclass
class QueryContext:
    request: DNSRecord
    qtype: int              # QTYPE.A, QTYPE.AAAA, QTYPE.TXT
    qname: str              # Original qname (case-preserved)
    qname_lower: str        # Lowercased for matching
    client_ip: str
    client_port: int
    parts: List[str]        # Lowercased parts (e.g., ["24", "cidr"])
    original_parts: List[str]  # Case-preserved parts for payloads
```

### 3. Rule Pattern (`main.py:Rule`)

```python
class Rule(NamedTuple):
    name: str                              # Human-readable name for logging
    matcher: Callable[[QueryContext], Optional[Dict[str, Any]]]
    handler: Callable[..., DNSRecord]
```

**Matcher** returns:
- `Dict[str, Any]` with extracted parameters → handler called with `**params`
- `None` → rule doesn't match, try next rule

**Handler** receives `(ctx: QueryContext, **params)` → returns `DNSRecord`

### 4. Caching Layer (`Resolver._get_public_ips`)

- 5-minute TTL (configurable via `cache_ttl` in `Resolver.__init__`)
- Caches both IPv4 and IPv6
- Fallback to loopback on fetch failure
- Logged at INFO level on cache miss

## Utility Modules (`utils/`)

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `cidr_utils.py` | CIDR math | `calculate_usable_ips(prefix)` |
| `ip_utils.py` | IP validation, conversion | `is_valid_ipv4`, `is_valid_ipv6`, `subnet_mask_from_prefix`, `int_to_ip` |
| `ip_fetch_utils.py` | Public IP fetching | `fetch_ipv4()`, `fetch_ipv6()` with fallback services |
| `time_utils.py` | Time utilities | `get_current_time()`, `get_current_second()` |
| `base64_utils.py` | Base64 encode/decode | `encode_base64()`, `decode_base64()` |

## DNS Record Types Supported

| QTYPE | Use Cases |
|-------|-----------|
| `A` | IPv4 addresses (subnet mask, server IP, client IP, time-based IP) |
| `AAAA` | IPv6 addresses (server IP, client IP) |
| `TXT` | Text responses (CIDR count, time string, IPs as text, Base64, case transforms) |

## Adding New Features

Per `README.md`:
1. Add utility functions in appropriate `utils/` module
2. Add matcher: `_match_<feature>(self, ctx) -> Optional[Dict]`
3. Add handler: `_reply_<feature>(self, ctx, **kwargs) -> DNSRecord`
4. Register in `self.rules` list in `Resolver.__init__`
5. Add tests in `tests/test_resolver.py`
6. Update `README.md` with examples

## Design Decisions (from git history)

| Commit | Decision | Rationale |
|--------|----------|-----------|
| `8db1cfd` | Rule registry pattern | Replaced monolithic `resolve()` with composable matcher/handler rules |
| `8db1cfd` | `QueryContext` dataclass | Centralized parsed query data, avoids repeated parsing |
| `8db1cfd` | `_match_prefix_payload` helper | DRY for `b64.`, `d64.`, `lower.`, `upper.`, `up.` prefixes |
| `530ef0f` | Added `lower.`, `upper.`, `up.` case transforms | New case conversion features via DNS |
| `8db1cfd` | Structured logging | Structured log format with query details for debugging |
| `e60f626` | 5-min IP cache TTL | Reduce external API calls, configurable via constructor |
| `530ef0f` | Case conversion features | Added `lower.`→UPPER, `UPPER`→`lower`, `up.`→UPPER transforms |