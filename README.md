# DNS Python Server

A powerful DNS server implementation in Python that provides various utility functions through DNS queries. This server supports CIDR calculations, time queries, IP address lookups, Base64 encoding/decoding, and more.

## Features

### 1. CIDR Calculations
- **Usable IPs**: Calculate the number of usable IP addresses in a subnet
- **Subnet Mask**: Get the subnet mask for a given CIDR prefix

### 2. Time Services
- **Current Time**: Get the current local time as a formatted string
- **Time-based IP**: Get a fake IP address based on current seconds
- **Railway to AM/PM**: Convert 24-hour format time to 12-hour format (e.g., `14:30:00` → `2:30:00 PM`)

### 3. IP Address Services
- **Server Public IP**: Retrieve the server's public IPv4 and IPv6 addresses
- **Client IP**: Get the client's IP address that made the DNS query

### 4. Base64 Utilities
- **Base64 Encode**: Encode text to Base64 format
- **Base64 Decode**: Decode Base64 encoded data

## Installation

### Prerequisites
- Python 3.11+
- Docker (optional, for containerized deployment)

### Install as Local Package / CLI Tool

#### Using `uv` (Recommended)
You can install and run this project globally using `uv` tools:
```bash
# Install the tool globally
uv tool install .

# Or install in editable mode for development
uv tool install --editable .

# Run the CLI tool from anywhere!
dnspython
```

#### Using standard `pip`
```bash
# Install in editable mode
pip install -e .

# Or install normally
pip install .
```

## Usage

### Starting the Server
Simply run the installed command-line tool:
```bash
dnspython
```
Or run the Python wrapper script:
```bash
python main.py
```

*Note: The server will automatically bind to an available ephemeral port chosen by the OS to avoid port conflicts. The assigned port and query examples will be displayed on startup.*

### Direct CLI Utilities
You can execute all utility functionalities directly from the terminal without starting the DNS server by specifying their respective flags:

```bash
# Print current local time
dnspython --ct

# Calculate usable IPs for a CIDR prefix (e.g. 24)
dnspython --cidr 24

# Get subnet mask for a CIDR prefix (e.g. 24)
dnspython --mask 24

# Convert 24-hour time to AM/PM format
dnspython --ampm "14:30:00"

# Base64 encode text
dnspython --b64-encode "hello"
# or short flag:
dnspython --b64e "hello"

# Base64 decode text
dnspython --b64-decode "aGVsbG8="
# or short flag:
dnspython --b64d "aGVsbG8="

# Convert text to uppercase
dnspython --upper "hello"

# Convert text to lowercase
dnspython --lower "HELLO"

# Get machine's public IPv4 and IPv6 addresses
dnspython --ip

# Get your local network IP address
dnspython --myip
```

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
dig @localhost -p <port> time TXT +short

# Get time-based IP (127.0.0.1-127.0.0.255)
dig @localhost -p <port> time A +short

# Convert 24-hour time to 12-hour AM/PM format (supports dots or dashes)
dig @localhost -p <port> ampm.14.30.00 TXT +short
dig @localhost -p <port> ampm.14-30-00 TXT +short
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

### Using as Python Package
The `utils` module can be imported and used directly in Python code:

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

## Project Structure

```
dnspython/
├── main.py                  # CLI wrapper script (backward-compatible)
├── utils/
│   ├── main.py              # Main DNS server entry point and resolver
│   ├── base64_utils.py      # Base64 encoding/decoding utilities
│   ├── cidr_utils.py        # CIDR calculation utilities
│   ├── ip_fetch_utils.py    # Public IP fetching utilities
│   ├── ip_utils.py          # IP validation and conversion utilities
│   └── time_utils.py        # Time-related utilities
├── Dockerfile               # Docker configuration
├── docker-compose.yml       # Docker Compose configuration
├── requirements.txt         # Python dependencies
└── pyproject.toml           # Python project configuration (exposes 'dnspython' CLI tool)
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
Run the comprehensive unit test suite:
```bash
# Run tests using uv (installs dev dependencies automatically)
uv run --extra dev pytest

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
