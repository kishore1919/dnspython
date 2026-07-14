---
type: "Feature"
title: "Feature Overview"
description: "Complete reference of DNS query types and their response formats"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["features", "dns", "reference", "api"]
---

## DNS Query Reference

All queries target the DNS server. The server binds to an OS-assigned ephemeral port by default (printed on startup). Use `-p <port>` in `dig` with the actual port shown at startup.

**Query Format**: `dig @<host> -p <port> <qname> <QTYPE> +short`

---

### 1. CIDR Calculations

#### Usable IPs (TXT)
```
dig @localhost -p <port> 24.cidr TXT +short
# → "254"
```
- **Pattern**: `<prefix>.cidr` (0-32)
- **QTYPE**: TXT
- **Response**: Number of usable IPs in subnet
- **Special cases**: /31 → 2, /32 → 1, /0 → 4294967294

#### Subnet Mask (A)
```
dig @localhost -p <port> 24.mask.cidr A +short
# → "255.255.255.0"
```
- **Pattern**: `<prefix>.mask.cidr` (0-32)
- **QTYPE**: A
- **Response**: IPv4 subnet mask

---

### 2. Time Services

#### Current Time (TXT)
```
dig @localhost -p <port> time TXT +short
# → "2025-07-14 16:45:30"
```
- **Pattern**: `time`
- **QTYPE**: TXT
- **Response**: Local time as `YYYY-MM-DD HH:MM:SS`

#### Time-based IP (A)
```
dig @localhost -p <port> time A +short
# → "127.0.0.45"  (where 45 = current second + 1)
```
- **Pattern**: `time`
- **QTYPE**: A
- **Response**: `127.0.0.<second+1>` (range 1-60)

#### Railway Time → AM/PM Conversion (TXT)
```
dig @localhost -p <port> ampm.14.30 TXT +short
# → "2:30 PM"

dig @localhost -p <port> ampm.14-30 TXT +short
# → "2:30 PM"
```
- **Pattern**: `ampm.<HH>.<MM>` or `ampm.<HH>-<MM>`
- **QTYPE**: TXT only
- **Response**: 12-hour format `H:MM AM/PM` (no leading zero on hour)
- **Validation**: Invalid times (e.g., 25:00, 12:60) return error text

### 3. IP Address Services

#### Server Public IPv4 (A)
```
dig @localhost -p <port> ip A +short
# → "203.0.113.10"
```
- **Pattern**: `ip`
- **QTYPE**: A
- **Response**: Server's public IPv4 (cached 5 min)

#### Server Public IPv6 (AAAA)
```
dig @localhost -p <port> ip AAAA +short
# → "2001:db8::10"
```
- **Pattern**: `ip`
- **QTYPE**: AAAA
- **Response**: Server's public IPv6 (cached 5 min)

#### Server Public IPs (TXT)
```
dig @localhost -p <port> ip TXT +short
# → "IPv4: 203.0.113.10, IPv6: 2001:db8::10"
```
- **Pattern**: `ip`
- **QTYPE**: TXT
- **Response**: Both IPs as text

#### Client IP (A/AAAA/TXT)
```
# IPv4 client
dig @localhost -p <port> myip A +short
# → "192.168.1.50"

# IPv6 client
dig @localhost -p <port> myip AAAA +short
# → "2001:db8::1"

# Any client (fallback)
dig @localhost -p <port> myip TXT +short
# → "192.168.1.50"
```
- **Pattern**: `myip`
- **QTYPE**: A (IPv4 client), AAAA (IPv6 client), TXT (any)
- **Response**: Client's source IP from query
- **Type mismatch fallback**: IPv4 client asking AAAA → TXT response

---

### 4. Base64 Utilities

#### Encode (TXT)
```
dig @localhost -p 20000 b64.hello TXT +short
# → "aGVsbG8="
```
- **Pattern**: `b64.<text>` (dots preserved in payload)
- **QTYPE**: TXT only
- **Response**: Base64 encoded UTF-8

#### Decode (TXT)
```
dig @localhost -p <port> d64.aGVsbG8= TXT +short
# → "hello"
```
- **Pattern**: `d64.<base64>` (dots preserved)
- **QTYPE**: TXT only
- **Response**: Decoded UTF-8 text, or `"Invalid base64"` on error
- **Padding**: Auto-handles missing `=` padding

---

### 5. Case Conversion

#### Lowercase → UPPERCASE (TXT)
```
dig @localhost -p <port> lower.hello TXT +short
# → "HELLO"

dig @localhost -p <port> lower.foo.bar TXT +short
# → "FOO.BAR"
```
- **Pattern**: `lower.<text>`
- **QTYPE**: TXT only
- **Response**: Uppercased payload

#### UPPERCASE → lowercase (TXT)
```
dig @localhost -p <port> upper.HELLO TXT +short
# → "hello"

dig @localhost -p <port> upper.FOO.BAR TXT +short
# → "foo.bar"
```
- **Pattern**: `upper.<TEXT>`
- **QTYPE**: TXT only
- **Response**: Lowercased payload

#### Echo as UPPERCASE (TXT)
```
dig @localhost -p <port> up.hello TXT +short
# → "HELLO"
```
- **Pattern**: `up.<text>`
- **QTYPE**: TXT only
- **Response**: Uppercased payload (same as `lower.` but different semantic)

---

### 6. Railway Time → AM/PM Conversion (TXT)
```
dig @localhost -p <port> ampm.14.30 TXT +short
# → "2:30 PM"

dig @localhost -p <port> ampm.14-30 TXT +short
# → "2:30 PM"
```
- **Pattern**: `ampm.<HH>.<MM>` or `ampm.<HH>-<MM>`
- **QTYPE**: TXT only
- **Response**: 12-hour format `H:MM AM/PM` (no leading zero on hour)
- **Validation**: Invalid times (e.g., 25:00, 12:60) return error text

---

## QTYPE Support Matrix

| Feature | A | AAAA | TXT |
|---------|---|------|-----|
| `X.cidr` | ❌ | ❌ | ✅ |
| `X.mask.cidr` | ✅ | ❌ | ❌ |
| `time` | ✅ (fake IP) | ❌ | ✅ |
| `ampm.*` | ❌ | ❌ | ✅ |
| `ip` | ✅ | ✅ | ✅ |
| `myip` | ✅* | ✅* | ✅ |
| `b64.*` | ❌ | ❌ | ✅ |
| `d64.*` | ❌ | ❌ | ✅ |
| `lower.*` | ❌ | ❌ | ✅ |
| `upper.*` | ❌ | ❌ | ✅ |
| `up.*` | ❌ | ❌ | ✅ |

*Type mismatch falls back to TXT

---

## CLI Tool Reference (NEW)

The `dnspython` CLI tool (installed via `uv tool install .` or `pip install -e .`) provides direct access to all utilities without starting a DNS server:

```bash
# Time utilities
dnspython --ct                    # Print current local time
dnspython --ampm "14:30:00"      # Convert 24h to 12h format

# CIDR utilities
dnspython --cidr 24              # Usable IPs for /24
dnspython --mask 24              # Subnet mask for /24

# Base64 utilities
dnspython --b64-encode "hello"   # Base64 encode
dnspython --b64-decode "aGVsbG8=" # Base64 decode
# Short flags: --b64e, --b64d

# Case conversion
dnspython --upper "hello"        # Convert to UPPERCASE
dnspython --lower "HELLO"        # Convert to lowercase

# IP utilities
dnspython --ip                   # Server's public IPv4 and IPv6
dnspython --myip                 # Your local network IP

# DNS Server mode (default, no flags)
dnspython                        # Start DNS server on ephemeral port
dnspython -a 0.0.0.0             # Bind to all interfaces
```

---

## Using as Python Package

```python
from utils import convert_railway_to_ampm, get_current_time, encode_base64

# Convert railway time to AM/PM format
print(convert_railway_to_ampm("14:30:00"))  # Output: 2:30:00 PM
print(convert_railway_to_ampm("00:00:00"))  # Output: 12:00:00 AM

# Get current time
print(get_current_time())  # Output: 2026-07-14 14:30:00

# Base64 encode
print(encode_base64("hello"))  # Output: aGVsbG8=
```

## Response Behavior

| Scenario | Behavior |
|----------|----------|
| Unknown query | Empty response (no answers) |
| Wrong QTYPE for feature | Empty response (no answers) |
| Handler exception | Empty response, error logged |
| Fatal resolver error | Empty response, error logged |
| IP fetch failure | Falls back to localhost (127.0.0.1 / ::1) |
| Base64 decode error | Returns `"Invalid base64"` as TXT |
| Invalid CIDR prefix (not 0-32) | No match → empty response |
| Case conversion wrong QTYPE | Empty response |

---

## Logging

Structured logging at INFO level:
```
2025-07-14 16:45:30 [INFO] dnspython: Query from 127.0.0.1:12345: 24.cidr (type=TXT)
2025-07-14 16:45:30 [DEBUG] dnspython: Matched rule 'CIDR Usable IPs' with args: {'prefix': 24}
```

Set `LOG_LEVEL=DEBUG` to see rule matching details.