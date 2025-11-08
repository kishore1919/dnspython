# dnspython

A Python library for DNS operations.

## Installation

Install the library and dependencies:

```bash
pip install -r requirements.txt
```

## Testing on Windows

To run tests on Windows using Command Prompt or PowerShell:

1. Ensure Python and pip are installed.

2. Install test dependencies (if not already in requirements.txt):
   ```
   pip install pytest
   ```

3. Run the tests:
   ```
   python -m pytest
   ```

For Docker-based testing (using the provided Dockerfile):

1. Build the image:
   ```
   docker build -t dnspython .
   ```

2. Run tests inside the container:
   ```
   docker run --rm dnspython python -m pytest
   ```

Note: Adjust paths and commands as needed for your environment.

## Troubleshooting

### nslookup Fails with "No response from server"

If running `nslookup -type=A -port=20000 ip localhost` on Windows results in "UnKnown can't find ip: No response from server":

- **Ensure the server is running**: Confirm `python main.py` is executed and the server is listening on port 20000. Check for any error messages in the console.
- **Check network interface**: `localhost` resolves to `::1` (IPv6) by default on some systems. Try using `127.0.0.1` (IPv4) instead: `nslookup -type=A -port=20000 ip 127.0.0.1`.
- **Firewall or port issues**: Ensure port 20000 is not blocked by Windows Firewall or antivirus. Temporarily disable them for testing.
- **IPv6 compatibility**: If the server only listens on IPv4, force IPv4 in nslookup: `nslookup -type=A -port=20000 ip 127.0.0.1`.
- **Use dig instead**: As an alternative, install dig (e.g., via BIND tools) and use `dig @127.0.0.1 -p 20000 ip A` for more reliable results.
- **Server logs**: Add logging to `main.py` to verify queries are received.

If issues persist, check the server code for binding to the correct address (e.g., `0.0.0.0` for all interfaces).

## Features

- **CIDR Calculator**:
  - `dig @localhost -p 20000 <prefix>.cidr TXT`: Get the number of usable IPs in a CIDR network.
  - `dig @localhost -p 20000 <prefix>.mask.cidr A`: Get the subnet mask for a given CIDR prefix.
- **Time**:
  - `dig @localhost -p 20000 time TXT`: Get the current server time.
- **IP Address**:
  - `dig @localhost -p 20000 ip A`: Get the server's public IPv4 address.
  - `dig @localhost -p 20000 ip AAAA`: Get the server's public IPv6 address.
  - `dig @localhost -p 20000 ip TXT`: Get both IPv4 and IPv6 addresses.
- **Client IP**:
  - `dig @localhost -p 20000 myip A/AAAA/TXT`: Get the client's IP address.
- **Base64 Encoding/Decoding**:
  - `dig @localhost -p 20000 b64.<text> TXT`: Encode text to base64.
  - `dig @localhost -p 20000 d64.<base64> TXT`: Decode a base64 string.

## Requirements

- Python 3.6+
- `dnspython` and `dnslib` libraries (`pip install dnspython dnslib requests`)

## Usage

0. Fetch required data:
   ```bash
   scripts/fetch-all-details.sh
   ```

1. Start the DNS server:
   ```bash
   python main.py
   ```

2. Query the server using `dig`. See the "Features" section for examples.

## How It Works

The server listens on port 20000 and responds to various DNS queries with calculated results or information. It can perform CIDR calculations, provide time and IP address information, and encode/decode base64 strings, all through DNS queries.
