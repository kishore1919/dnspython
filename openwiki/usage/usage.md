# Usage Guide

The DNS Python Server provides multiple utility services through a unified DNS query interface. This guide explains how to effectively use the available features and understand the query naming conventions.

## Core Query Patterns

### 1. CIDR Calculations
- **Usage**: `X.cidr` (TXT record) and `X.mask.cidr` (A record)
- **Examples**:
  - `dig @localhost -p 20000 192.168.1.0/24.cidr TXT +short` → usable IPs in /24 subnet
  - `dig @localhost -p 20000 192.168.1.0/24.mask.cidr A +short` → subnet mask for /24

### 2. Time Services
- **Usage**: `time` domain (TXT or A record)
- **Examples**:
  - `dig @localhost -p 20000 time TXT +short` → current time string
  - `dig @localhost -p 20000 time A +short` → time-based IP address

### 3. IP Address Services
- **Usage**: `ip` or `myip` domains
- **Examples**:
  - `dig @localhost -p 20000 ip A +short` → server's IPv4
  - `dig @localhost -p 20000 ip AAAA +short` → server's IPv6
  - `dig @localhost -p 20000 myip A +short` → client's IP address
  - `dig @localhost -p 20000 myip TXT +short` → client IP as text

### 4. Base64 Utilities
- **Usage**: `b64.` prefix for encoding, `d64.` prefix for decoding
- **Examples**:
  - `dig @localhost -p 20000 b64.hello TXT +short` → encodes "hello"
  - `dig @localhost -p 20000 d64.aGVsbG8 TXT +short` → decodes "hello"

## Query Structure
All queries follow the pattern: `[domain].[subdomain].[tld]`
- Domain determines the service category (cidr, mask, time, ip, myip, b64, d64)
- Subdomain often contains additional parameters (e.g., prefix for CIDR)
- TLD (top-level domain) is typically ignored in most query types

## Response Types
Responses vary by query type and requested record type (A, AAAA, TXT):
- CIDR calculations: TXT for large numbers, A for subnet masks
- Time services: TXT for human-readable time, A for time-based IPs
- Base64 utilities: Always TXT records for both encoding and decoding
- IP services: A/AAAA for IP addresses, TXT for textual representation

## Best Practices
- Use consistent query patterns for predictable results
- Check documentation for specific response type expectations
- Test queries with small payloads before scaling up
- Be mindful of rate limits during development