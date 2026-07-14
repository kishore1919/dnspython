---
type: "Feature"
title: "Feature Overview"
description: "Complete reference of DNS query types and their response formats"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["features", "dns", "reference", "api"]
---

## DNS Query Reference

All queries target the DNS server at `localhost:20000` (configurable via `DNS_PORT`/`DNS_ADDRESS`).

**Query Format**: `dig @<host> -p <port> <qname> <QTYPE> +short`

---

### 1. CIDR Calculations

#### Usable IPs (TXT)
```
dig @localhost -p 20000 24.cidr TXT +short
# → "254"
```
- **Pattern**: `<prefix>.cidr` (0-32)
- **QTYPE**: TXT
- **Response**: Number of usable IPs in subnet
- **Special cases**: /31 → 2, /32 → 1, /0 → 4294967294

#### Subnet Mask (A)
```
dig @localhost -p 20000 24.mask.cidr A +short
# → "255.255.255.0"
```
- **Pattern**: `<prefix>.mask.cidr` (0-32)
- **QTYPE**: A
- **Response**: IPv4 subnet mask

---

### 2. Time Services

#### Current Time (TXT)
```
dig @localhost -p 20000 time TXT +short
# → "2025-07-14 16:45:30"
```
- **Pattern**: `time`
- **QTYPE**: TXT
- **Response**: Local time as `YYYY-MM-DD HH:MM:SS`

#### Time-based IP (A)
```
dig @localhost -p 20000 time A +short
# → "127.0.0.45"  (where 45 = current second + 1)
```
- **Pattern**: `time`
- **QTYPE**: A
- **Response**: `127.0.0.<second+1>` (range 1-60)

---

### 3. IP Address Services

#### Server Public IPv4 (A)
```
dig @localhost -p 20000 ip A +short
# → "203.0.113.10"
```
- **Pattern**: `ip`
- **QTYPE**: A
- **Response**: Server's public IPv4 (cached 5 min)

#### Server Public IPv6 (AAAA)
```
dig @localhost -p 20000 ip AAAA +short
# → "2001:db8::10"
```
- **Pattern**: `ip`
- **QTYPE**: AAAA
- **Response**: Server's public IPv6 (cached 5 min)

#### Server Public IPs (TXT)
```
dig @localhost -p 20000 ip TXT +short
# → "IPv4: 203.0.113.10, IPv6: 2001:db8::10"
```
- **Pattern**: `ip`
- **QTYPE**: TXT
- **Response**: Both IPs as text

#### Client IP (A/AAAA/TXT)
```
# IPv4 client
dig @localhost -p 20000 myip A +short
# → "192.168.1.50"

# IPv6 client
dig @localhost -p 20000 myip AAAA +short
# → "2001:db8::1"

# Any client (fallback)
dig @localhost -p 20000 myip TXT +short
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
dig @localhost -p 20000 d64.aGVsbG8= TXT +short
# → "hello"
```
- **Pattern**: `d64.<base64>` (dots preserved)
- **QTYPE**: TXT only
- **Response**: Decoded UTF-8 text, or `"Invalid base64"` on error
- **Padding**: Auto-handles missing `=` padding

---

### 5. Case Conversion (NEW in 530ef0f)

#### Lowercase → UPPERCASE (TXT)
```
dig @localhost -p 20000 lower.hello TXT +short
# → "HELLO"

dig @localhost -p 20000 lower.foo.bar TXT +short
# → "FOO.BAR"
```
- **Pattern**: `lower.<text>`
- **QTYPE**: TXT only
- **Response**: Uppercased payload

#### UPPERCASE → lowercase (TXT)
```
dig @localhost -p 20000 upper.HELLO TXT +short
# → "hello"

dig @localhost -p 20000 upper.FOO.BAR TXT +short
# → "foo.bar"
```
- **Pattern**: `upper.<TEXT>`
- **QTYPE**: TXT only
- **Response**: Lowercased payload

#### Echo as UPPERCASE (TXT)
```
dig @localhost -p 20000 up.hello TXT +short
# → "HELLO"
```
- **Pattern**: `up.<text>`
- **QTYPE**: TXT only
- **Response**: Uppercased payload (same as `lower.` but different semantic)

---

## QTYPE Support Matrix

| Feature | A | AAAA | TXT |
|---------|---|------|-----|
| `X.cidr` | ❌ | ❌ | ✅ |
| `X.mask.cidr` | ✅ | ❌ | ❌ |
| `time` | ✅ (fake IP) | ❌ | ✅ |
| `ip` | ✅ | ✅ | ✅ |
| `myip` | ✅* | ✅* | ✅ |
| `b64.*` | ❌ | ❌ | ✅ |
| `d64.*` | ❌ | ❌ | ✅ |
| `lower.*` | ❌ | ❌ | ✅ |
| `upper.*` | ❌ | ❌ | ✅ |
| `up.*` | ❌ | ❌ | ✅ |

*Type mismatch falls back to TXT

---

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