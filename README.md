# DNS Time Server

A simple DNS server that responds with the current local time when queried.

## Features

- Responds to DNS queries with the current local time
- Supports both TXT and A record queries
- Runs on localhost:5353 to avoid requiring root privileges

## Requirements

- Python 3.6+
- dnspython library
- dnslib library

## Installation

1. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Start the DNS server:
   ```bash
   python main.py
   ```
   
   Or use the provided script:
   ```bash
   ./start_server.sh
   ```

2. Query the server using dig:
   ```bash
   dig @localhost -p 5353 time.local TXT
   ```

   Or with nslookup:
   ```bash
   nslookup -type=TXT -port=5353 time.local localhost
   ```

## Testing

A test script is included to demonstrate the functionality:

```bash
python test_server.py
```

This script will:
1. Start the DNS server in the background
2. Perform sample TXT and A record queries
3. Display the results
4. Stop the server

## How It Works

The server listens on port 5353 (to avoid requiring root privileges) and responds to all DNS queries with the current local time in a TXT record. For A record queries, it also returns 127.0.0.1.

## Example Output

```
$ dig @localhost -p 5353 time.local TXT

; <<>> DiG 9.10.6 <<>> @localhost -p 5353 time.local TXT
; (2 servers found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
;; QUESTION SECTION:
;time.local.			IN	TXT

;; ANSWER SECTION:
time.local.		0	IN	TXT	"2025-08-12 23:51:39"

;; Query time: 2 msec
;; SERVER: 127.0.0.1#5353(127.0.0.1)
;; WHEN: Tue Aug 12 23:51:39 IST 2025
;; MSG SIZE  rcvd: 80
```