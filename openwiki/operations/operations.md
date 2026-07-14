---
type: "Operation"
title: "Operations & Runbook"
description: "Operational guidance for running, monitoring, and troubleshooting the DNS server"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["operations", "runbook", "troubleshooting", "monitoring"]
---

## Quick Start

```bash
# Direct run
python main.py

# With custom port/address
DNS_PORT=30000 DNS_ADDRESS=0.0.0.0 python main.py

# Docker
docker-compose up --build
```

Server binds to `127.0.0.1:20000` by default (UDP + TCP).

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_PORT` | `20000` | UDP/TCP port to bind |
| `DNS_ADDRESS` | `127.0.0.1` | Bind address (use `0.0.0.0` for all interfaces) |
| `LOG_LEVEL` | `INFO` | Python logging level (DEBUG, INFO, WARNING, ERROR) |

### Constructor Options

```python
Resolver(cache_ttl=300)  # IP cache TTL in seconds (default 5 min)
```

---

## Running in Production

### Docker (Recommended)

```yaml
# docker-compose.yml
services:
  dnspython:
    build: .
    container_name: dnspython_prod
    ports:
      - "20000:20000/udp"
      - "20000:20000/tcp"
    environment:
      - DNS_ADDRESS=0.0.0.0
      - DNS_PORT=20000
      - LOG_LEVEL=INFO
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "dig", "@localhost", "-p", "20000", "time", "TXT", "+short", "+timeout=2"]
      interval: 30s
      timeout: 5s
      retries: 3
```

**Note**: The default `docker-compose.yml` maps port 8000. For DNS, change to 20000/udp+tcp.

### Systemd Service (Linux)

```ini
# /etc/systemd/system/dnspython.service
[Unit]
Description=DNS Python Utility Server
After=network.target

[Service]
Type=simple
User=dnspython
WorkingDirectory=/opt/dnspython
Environment=DNS_ADDRESS=0.0.0.0
Environment=DNS_PORT=20000
Environment=LOG_LEVEL=INFO
ExecStart=/opt/dnspython/.venv/bin/python main.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Monitoring & Health Checks

### Health Check Query

```bash
# Quick health check - should return current time
dig @localhost -p 20000 time TXT +short +timeout=2
# Expected: "2025-07-14 16:45:30"
```

### Key Metrics to Monitor

| Metric | Method | Alert Threshold |
|--------|--------|-----------------|
| Process uptime | systemd/docker healthcheck | < 60s = restart loop |
| Query latency | `dig +time=2 +tries=1` | > 500ms |
| IP cache freshness | Log: "Fetching fresh public IPs" | > 5 min = external API issues |
| Error rate | Log: `[ERROR]` count | > 1/min = investigate |

### Log Format

```
2025-07-14 16:45:30 [INFO] dnspython: Query from 127.0.0.1:12345: 24.cidr (type=TXT)
2025-07-14 16:45:30 [DEBUG] dnspython: Matched rule 'CIDR Usable IPs' with args: {'prefix': 24}
2025-07-14 16:45:30 [INFO] dnspython: Fetching fresh public IPs...
2025-07-14 16:45:31 [INFO] dnspython: Cached IPs - IPv4: 203.0.113.10, IPv6: 2001:db8::10
```

---

## Troubleshooting

### Port Already in Use

```
OSError: [Errno 98] Address already in use
```

**Fix**:
```bash
# Find process on port 20000
ss -ulpn | grep :20000
lsof -i :20000

# Kill or change DNS_PORT
DNS_PORT=20001 python main.py
```

### DNS Queries Not Working

1. **Verify server is running**:
   ```bash
   ss -ulpn | grep :20000
   # Should show: udp UNCONN 0 0 127.0.0.1:20000 0.0.0.0:*
   ```

2. **Test locally**:
   ```bash
   dig @127.0.0.1 -p 20000 time TXT +short
   ```

3. **Check firewall** (if binding 0.0.0.0):
   ```bash
   # Linux
   iptables -A INPUT -p udp --dport 20000 -j ACCEPT
   iptables -A INPUT -p tcp --dport 20000 -j ACCEPT
   ```

### IP Fetch Failures

**Logs show**:
```
[WARNING] dnspython.ip_fetch: Failed to fetch IPv4 from https://ipv4.icanhazip.com: ...
[WARNING] dnspython.ip_fetch: Using IPv4 fallback: 127.0.0.1
```

**Causes**:
- No internet connectivity
- All IP services down
- DNS resolution failure for service hostnames

**Mitigation**:
- Server still responds with localhost IPs
- Check network/egress firewall
- Consider adding internal IP service as fallback

### High Memory/CPU

**Symptoms**: Process grows unbounded, CPU spikes

**Likely causes**:
- DNS amplification attack (unlikely on 127.0.0.1)
- Query loop (client re-querying rapidly)
- Logging at DEBUG level in production

**Fixes**:
- Bind to `127.0.0.1` only (default)
- Rate limit at network level
- Set `LOG_LEVEL=INFO` or `WARNING`

### Query Returns Empty Response

**Debug steps**:
1. Enable DEBUG logging: `LOG_LEVEL=DEBUG python main.py`
2. Check logs for "Matched rule" or "Unknown query"
3. Verify QTYPE matches feature (see [Feature Matrix](/features/features.md#qtype-support-matrix))
4. Test with known-good query: `dig @localhost -p 20000 time TXT +short`

---

## Maintenance

### Updating Dependencies

```bash
# Update uv lockfile
uv lock --upgrade

# Or manually update requirements.txt
pip install --upgrade dnslib requests
pip freeze > requirements.txt
```

### Log Rotation

Use systemd/journald or Docker logging driver:
```yaml
# docker-compose.yml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

### Backup/Restore

No persistent state (IP cache is in-memory, 5-min TTL). No backup needed.

---

## Security Considerations

| Aspect | Status | Notes |
|--------|--------|-------|
| Bind address | `127.0.0.1` default | Change to `0.0.0.0` only with firewall |
| Authentication | None | DNS has no auth; restrict network access |
| Rate limiting | None | Add at network level (iptables, cloud FW) |
| Amplification risk | Low | Small responses, no recursion |
| Data exposure | Public IPs only | No sensitive data in responses |

---

## Common Operational Tasks

### Change Port
```bash
DNS_PORT=5353 python main.py  # Requires root for <1024
```

### Verify All Features Work
```bash
# Quick smoke test
for q in "24.cidr TXT" "24.mask.cidr A" "time TXT" "ip TXT" "myip TXT" "b64.test TXT" "d64.dGVzdA== TXT" "lower.hello TXT" "upper.HELLO TXT" "up.world TXT"; do
  echo "Testing: $q"
  dig @localhost -p 20000 $q +short
done
```

### View Cache Status
```python
# In Python REPL or add endpoint
from main import Resolver
r = Resolver()
print(f"IPv4: {r._cached_ipv4}, IPv6: {r._cached_ipv6}, Age: {time.time() - r._cache_time:.0f}s")
```