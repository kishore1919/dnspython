# Testing Documentation

The DNS Python Server includes a comprehensive test suite designed to validate resolver functionality and ensure reliable operation of all DNS-based utilities.

## Test Structure

### Core Test Files
- `tests/test_resolver.py` - Integration tests covering all Rule domains:
  - CIDR calculations (usable IPs, subnet masks)
  - Time service responses
  - IP address retrieval
  - Base64 encoding/decoding
  - Client IP detection

### Testing Objectives
- **Functional Validation**: Verify correct output for each query type
- **Edge Case Testing**: Test boundary conditions like /31 and /32 CIDR prefixes
- **Response Format Checks**: Ensure proper DNS record types (A, AAAA, TXT) are returned
- **Integration Testing**: Validate interaction between Resolver, utility modules, and DNS client

### Running Tests
```bash
python -m pytest tests/test_resolver.py -v
```

### Test Coverage
The current test suite validates:
- Correct calculation of usable IPs for various CIDR prefixes
- Proper subnet mask generation for all supported prefix lengths
- Accurate time responses in both TXT and A formats
- Correct IP address resolution for server and client queries
- Base64 encoding/decoding accuracy across multiple payloads
- Client IP detection consistency

### Test Maintenance
New features should be accompanied with corresponding test cases. When adding new query types or modifying existing functionality, update the test suite to maintain coverage.