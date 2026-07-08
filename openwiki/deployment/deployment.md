# Deployment Guide

The DNS Python Server can be deployed either directly on a host system or via containerized Docker deployment. This guide covers both approaches and provides configuration details.

## Host System Deployment

### Prerequisites
- Python 3.12 or higher
- pip package manager

### Installation
```bash
pip install dnslib requests
```

### Running the Server
```bash
python main.py
```

The server will start on `localhost:20000` and display available query types in the console.

## Docker Deployment

### Configuration Files
- `Dockerfile`: Defines the build environment and startup behavior
- `docker-compose.yml`: Orchestrates container deployment
- `.dockerignore`: Excludes unnecessary files from the build context

### Build and Run
```bash
docker-compose up --build
```

The Docker setup automatically:
- Builds the image using the Dockerfile
- Starts the container with the server running `main.py` by default
- Displays a startup message confirming successful launch

### Configuration
The server can be configured through environment variables and command-line arguments:
- Custom port configuration (via `PORT` environment variable)
- Logging level adjustment (via `LOG_LEVEL` environment variable)
- Cache TTL settings for IP and time responses

### Volume Mounts (Optional)
- Mount custom `data/` directory for persistent storage of cached responses
- Mount configuration files for advanced deployment scenarios

## Startup Behavior
When the server starts, it:
1. Initializes logging with timestamped messages
2. Binds to `0.0.0.0:20000` by default
3. Displays a welcome message showing available DNS query types
4. Begins processing incoming DNS queries

The server maintains state for:
- Recent IP fetch results (cached for performance)
- Time-based response caching (TTL controlled)
- Rule-based query routing (maintained in memory)

## Advanced Deployment Options
- HTTPS termination with reverse proxy (NGINX, Traefik)
- Load balancing across multiple server instances
- Container orchestration (Kubernetes, Docker Swarm)
- Monitoring integration (Prometheus, Grafana)