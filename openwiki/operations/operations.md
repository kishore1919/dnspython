---
type: "Operation"
title: "Operations & Runbook"
description: "Operational guidance for running, monitoring, and troubleshooting the DNS server"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["operations", "runbook", "troubleshooting", "monitoring"]
---

## Quick Start

```bash
# Run via installed CLI tool (recommended)
dnspython

# Run via Python module
python -m utils.main

# With custom bind address (port is OS-assigned ephemeral by default)
DNS_ADDRESS=0.0.0.0 python -m utils.main
```

Server binds to `127.0.0.1` on an **OS-assigned ephemeral port** by default. The assigned port is printed on startup — use that port in `dig` commands.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_ADDRESS` | `127.0.0.1` | Bind address (use `0.0.0.0` for all interfaces) |
| `LOG_LEVEL` | `INFO` | Python logging level (DEBUG, INFO, WARNING, ERROR) |

**Note**: `DNS_PORT` is ignored — the server always binds to port `0` (OS-assigned ephemeral port). If you need a fixed port, edit the `port` argument in `main()` in `utils/main.py`.

### Constructor Options

```python
Resolver(cache_ttl=300)  # IP cache TTL in seconds (default 5 min)
```

### CLI Flags

```bash
dnspython --help                    # Show all options
dnspython -a 0.0.0.0                # Bind to all interfaces
dnspython --ct                      # Print current time and exit
dnspython --cidr 24                 # Calculate usable IPs for /24
dnspython --mask 24                 # Get subnet mask for /24
dnspython --ampm "14:30:00"         # Convert 24h time to 12h AM/PM
dnspython --b64-encode "hello"      # Base64 encode
dnspython --b64-decode "aGVsbG8="   # Base64 decode
dnspython --upper "hello"           # Convert to uppercase
dnspython --lower "HELLO"           # Convert to lowercase
dnspython --ip                      # Get public IPv4 and IPv6
dnspython --myip                    # Get local network IP
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
      - LOG_LEVEL=INFO
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "dig", "@localhost", "-p", "20000", "time", "TXT", "+short", "+timeout=2"]
      interval: 30s
      timeout: 5s
      retries: 3
```

**Note**: The default `docker-compose.yml` maps port 8000. For DNS, override to map 20000/udp+tcp as shown above. The container runs with `port=0` (ephemeral), but Docker's port mapping uses the fixed port 20000.

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
# Use the actual port printed at startup (or 20000 in Docker with port mapping)
dig @localhost -p <actual_port> time TXT +short +timeout=2
# Expected: "2025-07-14 16:45:30"
```

In Docker with the port mapping above, use port 20000:
```bash
dig @localhost -p 20000 time TXT +short +timeout=2
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

The server uses an OS-assigned ephemeral port by default (`port=0`), so port conflicts are unlikely. If you need a fixed port (e.g., for Docker health checks or firewall rules), edit the `port` argument in `main()` in `utils/main.py`.

If you do encounter a port conflict:

### DNS Queries Not Working

1. **Verify server is running** (check the actual port printed at startup):
   ```bash
   # The server logs its actual port on startup, e.g.:
   # 2025-07-14 16:45:30 [INFO] dnspython: DNS Server running on 127.0.0.1:54321
   ss -ulpn | grep dnspython
   # Or check logs for the actual port
   ```

2. **Test locally** (use the actual port from logs):
   ```bash
   dig @127.0.0.1 -p <actual_port> time TXT +short
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