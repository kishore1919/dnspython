---
type: Quickstart
title: DNS Python Server - Quickstart
description: Get started with the DNS Python Server - a DNS utility server providing CIDR, time, IP, Base64, and case conversion services via DNS queries.
timestamp: 2025-07-14T16:45:00Z
tags: [quickstart, getting-started, dns, dns-server]
resource: /README.md
---

# DNS Python Server - Quickstart

A DNS utility server implemented in Python using `dnslib`. It exposes utility functions through standard DNS queries (A, AAAA, TXT records) on port 20000 by default.

## Quick Start

### Run with Python
```bash
# Install dependencies
pip install dnslib requests

# Run the server
python main.py
```

### Run with Docker
```bash
docker-compose up --build
```

The server starts on `127.0.0.1:20000` by default. Configure with:
- `DNS_PORT` (default: `20000`)
- `DNS_ADDRESS` (default: `127.0.0.1`)

## Quick Query Examples

| Query | Record Type | Description |
|-------|-------------|-------------|
| `dig @localhost -p 20000 24.cidr TXT` | TXT | Usable IPs in /24 subnet |
| `dig @localhost -p 20000 24.mask.cidr A` | A | Subnet mask for /24 |
| `dig @localhost -p 20000 time TXT` | TXT | Current time |
| `dig @localhost -p 20000 time A` | A | Time-based IP (127.0.0.1-127.0.0.255) |
| `dig @localhost -p 20000 ip A` | A | Server's public IPv4 |
| `dig @localhost -p 20000 ip AAAA` | AAAA | Server's public IPv6 |
| `dig @localhost -p 20000 ip TXT` | TXT | Both IPs as text |
| `dig @localhost -p 20000 myip A` | A | Your client IP |
| `dig @localhost -p 20000 b64.hello TXT` | TXT | Base64 encode "hello" |
| `dig @localhost -p 20000 d64.aGVsbG8 TXT` | TXT | Base64 decode "aGVsbG8" |
| `dig @localhost -p 20000 lower.hello TXT` | TXT | lowercase → UPPERCASE |
| `dig @localhost -p 20000 upper.HELLO TXT` | TXT | UPPERCASE → lowercase |
| `dig @localhost -p 20000 up.hello TXT` | TXT | Echo as UPPERCASE |

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Rule-based Resolver** | Each query type is handled by a registered `Rule` (matcher + handler) |
| **QueryContext** | Context object carrying parsed query data through the pipeline |
| **Caching** | Public IPs cached for 5 minutes (TTL configurable) |
| **DNS Record Types** | A (IPv4), AAAA (IPv6), TXT (text) |

## Documentation Structure

| Page | Description |
|------|-------------|
| [Architecture Overview](/openwiki/architecture/overview.md) | High-level architecture, resolver pipeline, rule registry |
| [Source Map](/openwiki/architecture/source-map.md) | File-by-file source map with key classes/functions |
| [Features](/openwiki/features/features.md) | Detailed feature reference with query examples |
| [Operations](/openwiki/operations/operations.md) | Running, logging, config, troubleshooting |
| [Testing](/openwiki/testing/testing.md) | Test structure, running tests, adding tests |
| [Deployment](/openwiki/deployment/deployment.md) | Docker, environment variables, production notes |

## Quick Links

- **Entry point**: `main.py:main()`
- **Resolver class**: `main.py:Resolver`
- **Rule registry**: `Resolver.__init__` → `self.rules`
- **Utility modules**: `utils/ip_utils.py`, `utils/cidr_utils.py`, `utils/base64_utils.py`, `utils/ip_fetch_utils.py`, `utils/time_utils.py`
- **Tests**: `tests/test_resolver.py`
- **Docker**: `Dockerfile`, `docker-compose.yml`