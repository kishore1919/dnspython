# Features Overview

The DNS Python Server provides a comprehensive set of DNS-based utility services that can be categorized into four main domains:

## 1. CIDR Calculations
- **Purpose**: Network planning and IP management
- **Capabilities**: 
  - Calculate usable IP addresses in a subnet (`X.cidr`)
  - Generate subnet masks for CIDR prefixes (`X.mask.cidr`)
- **Technical Details**: 
  - Implemented in `cidr_utils.py` with `calculate_usable_ips()` function
  - Handles special cases like /31 (2 usable IPs) and /32 (1 host)

## 2. Time Services
- **Purpose**: Time-related queries and time-based addressing
- **Capabilities**:
  - Return current server time (`time` domain)
  - Generate time-based IPs for client addressing
  - Provide time-stamped responses
- **Technical Details**:
  - Handles `time` domain queries in `time_utils.py`
  - Supports both TXT and A record responses

## 3. IP Address Services
- **Purpose**: Network diagnostics and discovery
- **Capabilities**:
  - Return server's public IPv4 (`ip`) and IPv6 (`ip AAAA`)
  - Return client's observed IP address (`myip`)
  - Text-based IP representation (`ip TXT`)
- **Technical Details**:
  - Uses `ip_fetch_utils.py` for public IP discovery
  - Implements client IP detection logic

## 4. Base64 Utilities
- **Purpose**: Text encoding/decoding through DNS queries
- **Capabilities**:
  - Encode arbitrary text to Base64 (`b64.<text>`)
  - Decode Base64 data (`d64.<data>`)
- **Technical Details**:
  - Implemented with strict domain validation in `base64_utils.py`
  - Uses `.` as payload separator for multi-part encoding/decoding

## Integration Approach
All features are exposed through a unified DNS server interface in `main.py`. New functionality can be added by:
1. Creating a new matcher function in the Resolver class
2. Implementing the corresponding handler
3. Adding the rule to the rules list
4. Implementing utility functions in the appropriate utils module

This architecture enables modular extension of DNS-based services while maintaining a consistent query interface.