# DNS Python Server - Quickstart

Welcome to the DNS Python Server! This repository provides a powerful DNS server implementation in Python that exposes a variety of utility functions through DNS queries. Use it to perform CIDR calculations, retrieve current time, fetch public IP addresses, encode/decode Base64, and more.

## Repository Overview

- **Purpose**: DNS server that answers specialized queries for network utilities
- **Key Features**:
  - CIDR calculations (usable IPs, subnet masks)
  - Time services (current time, time-based IPs)
  - IP address services (public IP lookup, client IP detection)
  - Base64 encoding/decoding utilities
- **Directory Structure**:
  - `main.py` - Core server implementation and resolver logic
  - `utils/` - Supporting utility modules:
    - `base64_utils.py`
    - `cidr_utils.py`
    - `ip_fetch_utils.py`
    - `ip_utils.py`
    - `time_utils.py`
  - `tests/` - Test suite for resolver functionality
  - `docker/` - Docker deployment configuration (Dockerfile, docker-compose.yml)

## Quick Start

### Running Locally

1. Install dependencies:
   ```bash
   pip install dnslib requests
   ```

2. Start the server:
   ```bash
   python main.py
   ```

3. The server will run on `localhost:20000` and respond to DNS queries at that endpoint.

### Using Docker (Recommended)

1. Build and run with Docker Compose:
   ```bash
   docker-compose up --build
   ```

2. The server will start automatically and display a startup message.

### Making Queries

Use any DNS client (e.g., `dig`) to query the server at `localhost:20000`. Query patterns include:

- **CIDR Calculations**: 
  - `dig @localhost -p 20000 24.cidr TXT +short` → usable IPs in /24 subnet
  - `dig @localhost -p 20000 24.mask.cidr A +short` → subnet mask for /24

- **Time Services**:
  - `dig @localhost -p 20000 time TXT +short` → current time string
  - `dig @localhost -p 20000 time A +short` → time-based IP

- **IP Services**:
  - `dig @localhost -p 20000 ip A +short` → server's public IPv4
  - `dig @localhost -p 20000 myip A +short` → client's IP address

- **Base64 Utilities**:
  - `dig @localhost -p 20000 b64.hello TXT +short` → encodes "hello"
  - `dig @localhost -p 20000 d64.aGVsbG8 TXT +short` → decodes "hello"

## Next Steps

- Explore the [Architecture Overview](openwiki/architecture/overview.md) for technical details
- Review [Features](openwiki/features/feature-overview.md) for complete capability list
- See [Usage Examples](openwiki/usage/usage.md) for more query patterns
- Check [Deployment Guide](openwiki/deployment/deployment.md) for Docker-specific instructions
- Learn about [Testing Practices](openwiki/testing/testing.md) for contribution guidelines

Start experimenting with DNS queries to discover the available utilities!