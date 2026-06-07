# DNS Python Server

A powerful DNS server implementation in Python that provides various utility functions through DNS queries. This server supports CIDR calculations, time queries, IP address lookups, Base64 encoding/decoding, and more.

## Features

### 1. CIDR Calculations
- **Usable IPs**: Calculate the number of usable IP addresses in a subnet
- **Subnet Mask**: Get the subnet mask for a given CIDR prefix

### 2. Time Services
- **Current Time**: Get the current local time as a formatted string
- **Time-based IP**: Get a fake IP address based on current seconds

### 3. IP Address Services
- **Server Public IP**: Retrieve the server's public IPv4 and IPv6 addresses
- **Client IP**: Get the client's IP address that made the DNS query

### 4. Base64 Utilities
- **Base64 Encode**: Encode text to Base64 format
- **Base64 Decode**: Decode Base64 encoded data

## Installation

### Prerequisites
- Python 3.12+
- Docker (optional, for containerized deployment)

### Using pip
```bash
pip install dnslib requests
```

### Using Docker
```bash
docker-compose up --build
```

## Usage

### Starting the Server
```bash
python main.py
```

The server will run on `localhost:20000` and display available query types.

### DNS Query Examples

#### CIDR Calculations
```bash
# Get number of usable IPs for /24 subnet
dig @localhost -p 20000 24.cidr TXT +short

# Get subnet mask for /24 prefix
dig @localhost -p 20000 24.mask.cidr A +short
```

#### Time Services
```bash
# Get current time
dig @localhost -p 20000 time TXT +short

# Get time-based IP (127.0.0.1-127.0.0.255)
dig @localhost -p 20000 time A +short
```

#### IP Address Services
```bash
# Get server's public IPv4
dig @localhost -p 20000 ip A +short

# Get server's public IPv6
dig @localhost -p 20000 ip AAAA +short

# Get server's public IPs as text
dig @localhost -p 20000 ip TXT +short

# Get your client IP
dig @localhost -p 20000 myip A +short
```

#### Base64 Utilities
```bash
# Base64 encode 'hello'
dig @localhost -p 20000 b64.hello TXT +short

# Base64 decode 'aGVsbG8' (which is 'hello')
dig @localhost -p 20000 d64.aGVsbG8 TXT +short
```

## Project Structure

```
dnspython/
├── main.py                  # Main DNS server implementation
├── utils/
│   ├── base64_utils.py      # Base64 encoding/decoding utilities
│   ├── cidr_utils.py        # CIDR calculation utilities
│   ├── ip_fetch_utils.py    # Public IP fetching utilities
│   ├── ip_utils.py          # IP validation and conversion utilities
│   └── time_utils.py        # Time-related utilities
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose configuration
├── requirements.txt         # Python dependencies
└── pyproject.toml           # Python project configuration
```

## Technical Details

### DNS Query Types Supported
- **A Records**: IPv4 addresses
- **AAAA Records**: IPv6 addresses
- **TXT Records**: Text data

### Caching
- Public IP addresses are cached for 5 minutes to reduce external API calls

### Error Handling
- Graceful fallback for failed IP fetches
- Proper error handling for Base64 operations
- Validation for CIDR prefixes and IP addresses

## Development

### Running Tests
Run the comprehensive unit test suite using python or uv:
```bash
# Run tests using uv
uv run python -m unittest tests/test_resolver.py

# Or using standard python
python -m unittest tests/test_resolver.py
```

### Adding New Features
1. Add new utility functions in the appropriate `utils/` module if needed.
2. In `Resolver` in `main.py`:
   - Implement a matcher method `_match_<feature>(self, ctx: QueryContext) -> Optional[Dict[str, Any]]` that matches the query domain patterns and returns a dictionary of extracted parameters.
   - Implement a response builder method `_reply_<feature>(self, ctx: QueryContext, **kwargs) -> DNSRecord`.
   - Register the rule in the `self.rules` list in `Resolver.__init__` using the `Rule` tuple:
     ```python
     Rule("Feature Name", self._match_<feature>, self._reply_<feature>)
     ```
3. Add tests in `tests/test_resolver.py` to cover the new logic.
4. Update this README with new query examples.

## Configuration

### Server Configuration
The server binds to `127.0.0.1:20000` by default. You can configure this using environment variables:
- `DNS_PORT`: Port to listen on (default: `20000`)
- `DNS_ADDRESS`: Address to bind to (default: `127.0.0.1`)

For example, to run on a different port:
```bash
# Windows PowerShell
$env:DNS_PORT="30000"
$env:DNS_ADDRESS="0.0.0.0"
python main.py
```

### IP Fetch Services
The server uses multiple public IP fetch services with fallback:
- IPv4: icanhazip.com, api.ipify.org, ident.me, ipecho.net
- IPv6: icanhazip.com, ident.me

## Troubleshooting

### Common Issues
- **Port already in use**: Change the `DNS_PORT` environment variable or stop the conflicting service.
- **DNS queries not working**: Ensure the server is running and check firewall/network settings.
- **IP fetch failures**: The server will log a warning and fall back to localhost loopback addresses.

### Debugging
The server uses structured logging to log all queries and execution traces. You can set the logging level or view the formatted stdout/stderr console logs.

## License
This project is open source and available for modification and distribution.

## Contributing
Contributions are welcome! Please submit pull requests with new features, bug fixes, or documentation improvements.
