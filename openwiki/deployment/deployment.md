---
type: "Deployment"
title: "Deployment Guide"
description: "Deployment options for the DNS Python Server: Docker, bare metal, systemd, and cloud"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["deployment", "docker", "kubernetes", "systemd", "production"]
---

## Deployment Options

| Method | Use Case | Complexity |
|--------|----------|------------|
| **Docker Compose** | Local dev, simple prod | Low |
| **Docker (standalone)** | Container orchestration | Low |
| **Kubernetes** | Production clusters | Medium |
| **Systemd (Linux VM)** | Bare metal / VM | Medium |
| **Python directly** | Development, testing | Lowest |

---

## Docker Deployment

### Dockerfile Analysis

```dockerfile
# Multi-stage build
FROM python:3.12-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.12-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
ENV PATH=/root/.local/bin:$PATH
ENV DNS_ADDRESS=0.0.0.0
EXPOSE 20000/udp 20000/tcp
CMD ["python", "main.py"]
```

**Key points**:
- Python 3.12 slim (smaller than 3.13)
- Multi-stage for smaller final image
- Installs deps in builder stage
- Exposes both UDP and TCP 20000
- Defaults to `0.0.0.0` with **OS-assigned ephemeral port** (`port=0` in code)
- The `DNS_PORT` environment variable is currently **ignored** by the server (uses ephemeral port)
- For fixed port in Docker, edit `utils/main.py` `main()` function's `port` argument

### docker-compose.yml

```yaml
services:
  dnspython:
    build: .
    container_name: dnspython
    ports:
      - "20000:20000/udp"   # Fixed port mapping for DNS
      - "20000:20000/tcp"
    volumes:
      - .:/app
    environment:
      - DNS_ADDRESS=0.0.0.0
      # DNS_PORT is currently ignored; server uses OS-assigned ephemeral port
      # Docker port mapping (above) makes it reachable on fixed host port 20000
```

**Note**: The server binds to `port=0` (ephemeral) inside the container. Docker's port mapping (`-p 20000:20000`) forwards traffic from host port 20000 to whatever ephemeral port the container uses. The `DNS_PORT` environment variable is currently not read by the server.

### Build & Run

```bash
# Build
docker-compose build

# Run (foreground)
docker-compose up

# Run (detached)
docker-compose up -d

# Logs
docker-compose logs -f

# Stop
docker-compose down
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
services:
  dnspython:
    build: .
    container_name: dnspython_prod
    restart: unless-stopped
    ports:
      - "20000:20000/udp"
      - "20000:20000/tcp"
    environment:
      - DNS_ADDRESS=0.0.0.0
      # DNS_PORT is currently ignored; server uses OS-assigned ephemeral port
      # Docker port mapping (above) makes it reachable on fixed host port 20000
      - LOG_LEVEL=INFO
    healthcheck:
      test: ["CMD", "dig", "@localhost", "-p", "20000", "time", "TXT", "+short", "+timeout=2"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

Run: `docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d`

---

## Kubernetes Deployment

### Deployment Manifest

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dnspython
  labels:
    app: dnspython
spec:
  replicas: 2
  selector:
    matchLabels:
      app: dnspython
  template:
    metadata:
      labels:
        app: dnspython
    spec:
      containers:
      - name: dnspython
        image: your-registry/dnspython:latest
        ports:
        - containerPort: 20000
          name: dns-udp
          protocol: UDP
        - containerPort: 20000
          name: dns-tcp
          protocol: TCP
        env:
        - name: DNS_ADDRESS
          value: "0.0.0.0"
        - name: DNS_PORT
          value: "20000"
        - name: LOG_LEVEL
          value: "INFO"
        livenessProbe:
          exec:
            command: ["dig", "@localhost", "-p", "20000", "time", "TXT", "+short", "+timeout=2"]
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          exec:
            command: ["dig", "@localhost", "-p", "20000", "time", "TXT", "+short", "+timeout=2"]
          initialDelaySeconds: 5
          periodSeconds: 10
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "200m"
```

### Service (UDP + TCP)

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: dnspython
spec:
  type: LoadBalancer  # Or ClusterIP for internal
  ports:
  - port: 53
    targetPort: 20000
    protocol: UDP
    name: dns-udp
  - port: 53
    targetPort: 20000
    protocol: TCP
    name: dns-tcp
  selector:
    app: dnspython
```

**Note**: DNS typically uses port 53. The service maps 53 → 20000.

### ConfigMap for Configuration

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: dnspython-config
data:
  DNS_ADDRESS: "0.0.0.0"
  DNS_PORT: "20000"
  LOG_LEVEL: "INFO"
  CACHE_TTL: "300"
```

---

## Systemd Deployment (Linux VM)

### Prerequisites

```bash
# Create user
sudo useradd -r -s /bin/false -d /opt/dnspython dnspython

# Install Python 3.12+
sudo apt update && sudo apt install -y python3.12 python3.12-venv

# Create directory
sudo mkdir -p /opt/dnspython
sudo chown dnspython:dnspython /opt/dnspython
```

### Application Setup

```bash
# As dnspython user
cd /opt/dnspython
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt  # or uv sync

# Copy application files
cp -r /path/to/source/* /opt/dnspython/
```

### Systemd Unit

```ini
# /etc/systemd/system/dnspython.service
[Unit]
Description=DNS Python Utility Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=dnspython
Group=dnspython
WorkingDirectory=/opt/dnspython
Environment=DNS_ADDRESS=0.0.0.0
Environment=DNS_PORT=20000
Environment=LOG_LEVEL=INFO
Environment=PATH=/opt/dnspython/.venv/bin:/usr/bin:/bin
ExecStart=/opt/dnspython/.venv/bin/python main.py
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/dnspython
CapabilityBoundingSet=CAP_NET_BIND_SERVICE  # Only if port < 1024
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

### Enable & Start

```bash
sudo systemctl daemon-reload
sudo systemctl enable dnspython
sudo systemctl start dnspython
sudo systemctl status dnspython
```

### Logs

```bash
# Follow logs
sudo journalctl -u dnspython -f

# Last 100 lines
sudo journalctl -u dnspython -n 100
```

---

## Bare Python (Development)

```bash
# Quick start
python main.py

# Custom config
DNS_PORT=20000 DNS_ADDRESS=0.0.0.0 LOG_LEVEL=DEBUG python main.py

# With uv
uv run python main.py
```

---

## Cloud Deployment Examples

### AWS ECS (Fargate)

```json
{
  "family": "dnspython",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::...:role/ecsTaskExecutionRole",
  "containerDefinitions": [{
    "name": "dnspython",
    "image": "your-account.dkr.ecr.region.amazonaws.com/dnspython:latest",
    "portMappings": [
      {"containerPort": 20000, "protocol": "udp"},
      {"containerPort": 20000, "protocol": "tcp"}
    ],
    "environment": [
      {"name": "DNS_ADDRESS", "value": "0.0.0.0"},
      {"name": "DNS_PORT", "value": "20000"},
      {"name": "LOG_LEVEL", "value": "INFO"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/dnspython",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "ecs"
      }
    },
    "healthCheck": {
      "command": ["CMD-SHELL", "dig @localhost -p 20000 time TXT +short +timeout=2"],
      "interval": 30,
      "timeout": 5,
      "retries": 3,
      "startPeriod": 10
    }
  }]
}
```

### Google Cloud Run

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: dnspython
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/startup-cpu-boost: "true"
    spec:
      containerConcurrency: 100
      containers:
      - image: gcr.io/PROJECT_ID/dnspython
        ports:
        - containerPort: 20000
        env:
        - name: DNS_ADDRESS
          value: "0.0.0.0"
        - name: DNS_PORT
          value: "20000"
        - name: LOG_LEVEL
          value: "INFO"
        resources:
          limits:
            cpu: "1"
            memory: "512Mi"
          requests:
            cpu: "100m"
            memory: "128Mi"
```

**Note**: Cloud Run is HTTP-focused. For UDP DNS, use Cloud Run with Cloud Load Balancing (TCP/UDP) or GKE.

---

## CI/CD Pipeline

### GitHub Actions (Build & Push)

```yaml
# .github/workflows/docker.yml
name: Docker Build & Push

on:
  push:
    branches: [main]
    tags: ['v*']

jobs:
  docker:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/metadata-action@v5
        id: meta
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=ref,event=branch
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=raw,value=latest,enable={{is_default_branch}}
      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
```

---

## Security Hardening Checklist

| Item | Docker | K8s | Systemd | Notes |
|------|--------|-----|---------|-------|
| Non-root user | ✅ (Dockerfile) | ✅ (securityContext) | ✅ (User=) | Python runs as root in builder only |
| Read-only root fs | ❌ | `readOnlyRootFilesystem: true` | `ProtectSystem=strict` | App writes no files |
| Drop capabilities | N/A | `drop: [ALL]` | `CapabilityBoundingSet=` | Only `NET_BIND_SERVICE` if port<1024 |
| Network policies | N/A | ✅ | N/A | Restrict to DNS clients only |
| Secrets management | N/A | ✅ (Secrets) | N/A | No secrets needed currently |
| Resource limits | ✅ (compose) | ✅ | ❌ | Set memory/CPU limits |

---

## Verification After Deploy

```bash
# 1. Basic connectivity
dig @<host> -p 20000 time TXT +short

# 2. All features
for q in "24.cidr TXT" "24.mask.cidr A" "time TXT" "ip TXT" "myip TXT" "b64.test TXT" "d64.dGVzdA== TXT" "lower.hello TXT" "upper.HELLO TXT" "up.world TXT"; do
  echo "Query: $q"
  dig @<host> -p 20000 $q +short
done

# 3. IPv6 (if available)
dig @<host> -p 20000 ip AAAA +short
dig @<host> -p 20000 myip AAAA +short  # from IPv6 client
```