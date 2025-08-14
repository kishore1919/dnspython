# DNS Utility Server

A simple DNS server that provides various utility functions.

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
