---
type: Quickstart
title: DNS Python Server - Quickstart
description: Get started with the DNS Python Server - a DNS utility server providing CIDR, time, IP, Base64, and case conversion services via DNS queries or CLI.
timestamp: 2025-07-14T16:45:00Z
tags: [quickstart, getting-started, dns, dns-server, cli]
resource: /README.md
---

# DNS Python Server - Quickstart

A DNS utility server implemented in Python using `dnslib`. It exposes utility functions through standard DNS queries (A, AAAA, TXT records) on an OS-assigned ephemeral port, plus a full CLI toolkit for direct utility access.

## Quick Start

### Install as CLI Tool (Recommended)

```bash
# Install globally with uv (recommended)
uv tool install .

# Or install in editable mode for development
uv tool install --editable .

# Run the CLI tool from anywhere
dnspython
```

Or with standard pip:

```bash
# Install in editable mode
pip install -e .

# Run the CLI tool
dnspython
```

### Direct Python Module Run

```bash
# Run the DNS server
python -m utils.main

# Run CLI utilities directly
python -m utils.main --ct        # Current time
python -m utils.main --cidr 24   # CIDR usable IPs
python -m utils.main --ampm "14:30:00"  # Time conversion
```

### Docker

```bash
docker-compose up --build
```

The server binds to `127.0.0.1` by default on an **OS-assigned ephemeral port** (port 0 = OS picks free port). The assigned port is printed on startup — use that port in `dig` commands below.

Configure bind address with:
- `DNS_ADDRESS` (default: `127.0.0.1`, use `0.0.0.0` for all interfaces)
- `-a, --address` CLI flag (overrides env var)

## Quick Query Examples

All `dig` examples below use `<port>` — replace with the port printed at server startup.

| Query | Record Type | Description |
|-------|-------------|-------------|
| `dig @localhost -p <port> 24.cidr TXT` | TXT | Usable IPs in /24 subnet |
| `dig @localhost -p <port> 24.mask.cidr A` | A | Subnet mask for /24 |
| `dig @localhost -p <port> time TXT` | TXT | Current time (YYYY-MM-DD HH:MM:SS) |
| `dig @localhost -p <port> time A` | A | Time-based IP (127.0.0.1-127.0.0.255) |
| `dig @localhost -p <port> ampm.14.30 TXT` | TXT | Convert 24h → 12h (2:30 PM) |
| `dig @localhost -p <port> ampm.14-30 TXT` | TXT | Convert with dashes |
| `dig @localhost -p <port> ip A` | A | Server's public IPv4 |
| `dig @localhost -p <port> ip AAAA` | AAAA | Server's public IPv6 |
| `dig @localhost -p <port> ip TXT` | TXT | Both IPs as text |
| `dig @localhost -p <port> myip A` | A | Your client IP |
| `dig @localhost -p <port> b64.hello TXT` | TXT | Base64 encode "hello" |
| `dig @localhost -p <port> d64.aGVsbG8 TXT` | TXT | Base64 decode "aGVsbG8" |
| `dig @localhost -p <port> lower.hello TXT` | TXT | lowercase → UPPERCASE |
| `dig @localhost -p <port> upper.HELLO TXT` | TXT | UPPERCASE → lowercase |
| `dig @localhost -p <port> up.hello TXT` | TXT | Echo as UPPERCASE |

## CLI Utility Flags (No Server Needed)

Run utilities directly without starting the DNS server:

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--ct`, `--current-time` | | Print current local time | `dnspython --ct` |
| `--cidr <prefix>` | | Usable IPs for CIDR prefix | `dnspython --cidr 24` |
| `--mask <prefix>` | | Subnet mask for CIDR prefix | `dnspython --mask 24` |
| `--ampm <time>` | | Convert 24h (HH:MM:SS) → 12h | `dnspython --ampm "14:30:00"` |
| `--b64-encode <text>` | `--b64e` | Base64 encode text | `dnspython --b64e "hello"` |
| `--b64-decode <data>` | `--b64d` | Base64 decode data | `dnspython --b64d "aGVsbG8="` |
| `--upper <text>` | `--ltu` | Convert to UPPERCASE | `dnspython --upper "hello"` |
| `--lower <text>` | `--utl` | Convert to lowercase | `dnspython --lower "HELLO"` |
| `--ip` | | Get public IPv4 & IPv6 | `dnspython --ip` |
| `--myip` | | Get local network IP | `dnspython --myip` |

## Using as Python Package

```python
from utils import convert_railway_to_ampm, get_current_time, encode_base64, decode_base64

# Time conversion
print(convert_railway_to_ampm("14:30:00"))  # 2:30:00 PM
print(convert_railway_to_ampm("00:00:00"))  # 12:00:00 AM

# Current time
print(get_current_time())  # 2025-07-14 14:30:00

# Base64
print(encode_base64("hello"))   # aGVsbG8=
print(decode_base64("aGVsbG8=")) # hello
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Rule-based Resolver** | Each query type handled by a registered `Rule` (matcher + handler) |
| **QueryContext** | Immutable context carrying parsed query data through pipeline |
| **Caching** | Public IPs cached for 5 minutes (TTL configurable) |
| **DNS Record Types** | A (IPv4), AAAA (IPv6), TXT (text) |
| **Ephemeral Port** | Server binds to port 0 → OS assigns free port (printed at startup) |
| **CLI Tool** | `dnspython` command exposes all utilities without DNS server |

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

- **Entry point**: `utils/main.py:main()`
- **Resolver class**: `utils/main.py:Resolver`
- **Rule registry**: `Resolver.__init__` → `self.rules`
- **Utility modules**: `utils/ip_utils.py`, `utils/cidr_utils.py`, `utils/base64_utils.py`, `utils/ip_fetch_utils.py`, `utils/time_utils.py`
- **CLI entry**: `utils/main.py:main()` (exposed as `dnspython` via `pyproject.toml`)
- **Tests**: `tests/test_resolver.py`
- **Docker**: `Dockerfile`, `docker-compose.yml`
- **Config**: `pyproject.toml` (project config, CLI entry point)