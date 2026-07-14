---
type: "Testing"
title: "Testing Guide"
description: "Test structure, running tests, adding new tests, and test patterns for the DNS server"
timestamp: "2025-07-14T16:45:00.000Z"
tags: ["testing", "unit-tests", "integration", "pytest", "unittest"]
---

## Test Structure

```
tests/
└── test_resolver.py    # Single comprehensive test file (unittest)
```

**Test count**: ~60 tests covering utilities + resolver integration

---

## Running Tests

### Using uv (recommended)
```bash
uv run python -m unittest tests.test_resolver -v
```

### Using standard Python
```bash
python -m unittest tests.test_resolver -v
```

### Run specific test class
```bash
python -m unittest tests.test_resolver.TestResolver -v
python -m unittest tests.test_resolver.TestIpUtils -v
```

---

## Test Organization

### Utility Unit Tests (Pure Functions)

| Class | Module Under Test | Coverage |
|-------|-------------------|----------|
| `TestIpUtils` | `utils/ip_utils.py` | IP validation, subnet mask, int↔IP conversion |
| `TestCidrUtils` | `utils/cidr_utils.py` | Usable IP calculations (incl. /31, /32 edge cases) |
| `TestBase64Utils` | `utils/base64_utils.py` | Encode/decode, unicode, padding, roundtrip, invalid input |
| `TestTimeUtils` | `utils/time_utils.py` | Time format, second range, railway→am/pm conversion |
| `TestIpFetchUtils` | `utils/ip_fetch_utils.py` | Mocked HTTP, fallback chain, error handling |

### Resolver Integration Tests

| Class | Focus |
|-------|-------|
| `TestResolver` | Full `Resolver.resolve()` pipeline with `DummyHandler` |
| `TestResolverMatchers` | Individual matcher methods in isolation |
| `TestResolverReplies` | Individual reply builder methods in isolation |

---

## Key Test Patterns

### 1. DummyHandler for Client IP Simulation

```python
class DummyHandler:
    def __init__(self, client_ip="127.0.0.1", client_port=12345):
        self.client_address = (client_ip, client_port)
```

Used to test `myip` responses with different client IPs (IPv4/IPv6).

### 2. QueryContext Factory

```python
def _make_ctx(qname: str, qtype: str = "TXT", client_ip: str = "127.0.0.1") -> QueryContext:
    request = DNSRecord.question(qname, qtype)
    qname_str = str(request.q.qname).strip(".")
    return QueryContext(
        request=request,
        qtype=request.q.qtype,
        qname=qname_str,
        qname_lower=qname_str.lower(),
        client_ip=client_ip,
        client_port=12345,
        parts=qname_str.lower().split("."),
        original_parts=qname_str.split("."),
    )
```

### 3. TXT Response Extractor

```python
def _txt(reply) -> str:
    return str(reply.rr[0].rdata).strip('"')
```

### 4. Mocking External Dependencies

**IP fetch (module-level)**:
```python
@patch("utils.ip_fetch_utils.requests.get")
def test_fetch_ipv4_success(self, mock_get):
    mock_get.return_value = MagicMock(text="8.8.8.8\n")
    self.assertEqual(fetch_ipv4(), "8.8.8.8")
```

**Resolver internal method (instance-level)**:
```python
@patch.object(Resolver, "_get_public_ips", return_value=("203.0.113.10", "2001:db8::10"))
def test_server_ip_a(self, _mock_ips):
    request = DNSRecord.question("ip", "A")
    reply = self.resolver.resolve(request, self.handler)
    self.assertEqual(str(reply.rr[0].rdata), "203.0.113.10")
```

### 5. Forcing Error Paths

```python
def test_resolve_handles_handler_exception(self):
    # Replace first rule's handler with one that raises
    self.resolver.rules = [
        self.resolver.rules[0]._replace(
            handler=MagicMock(side_effect=RuntimeError("boom"))
        )
    ]
    # Force match via mocked matcher
    always = MagicMock(return_value={"prefix": 24})
    self.resolver.rules[0] = self.resolver.rules[0]._replace(matcher=always)

    request = DNSRecord.question("24.cidr", "TXT")
    reply = self.resolver.resolve(request, self.handler)
    self.assertEqual(len(reply.rr), 0)  # Empty response on error
```

---

## Adding New Tests

### For New Utility Functions

1. Add test class or extend existing in `tests/test_resolver.py`
2. Follow naming: `Test<ModuleName>` (e.g., `TestNewUtils`)
3. Test: happy path, edge cases, error conditions

### For New Resolver Features

Per `README.md` and architecture:

1. **Matcher tests** → `TestResolverMatchers`
   ```python
   def test_match_new_feature(self):
       ctx = _make_ctx("new.param", "TXT")
       self.assertEqual(self.resolver._match_new_feature(ctx), {"param": "value"})
       self.assertIsNone(self.resolver._match_new_feature(_make_ctx("other")))
   ```

2. **Reply tests** → `TestResolverReplies`
   ```python
   def test_reply_new_feature(self):
       ctx = _make_ctx("new.param", "TXT")
       reply = self.resolver._reply_new_feature(ctx, param="value")
       self.assertEqual(_txt(reply), "expected")
   ```

3. **Integration tests** → `TestResolver`
   ```python
   def test_new_feature_end_to_end(self):
       request = DNSRecord.question("new.param", "TXT")
       reply = self.resolver.resolve(request, self.handler)
       self.assertEqual(len(reply.rr), 1)
       self.assertEqual(_txt(reply), "expected")
   ```

4. **Wrong QTYPE test** (important!)
   ```python
   def test_new_feature_wrong_qtype(self):
       request = DNSRecord.question("new.param", "A")  # Wrong type
       reply = self.resolver.resolve(request, self.handler)
       self.assertEqual(len(reply.rr), 0)
   ```

---

## Test Coverage Gaps (Known)

| Area | Status | Notes |
|------|--------|-------|
| IPv6 client IP (AAAA) | ✅ Covered | `test_client_ip_resolution` |
| CIDR edge cases (/31, /32) | ✅ Covered | `TestCidrUtils` |
| Base64 unicode | ✅ Covered | `test_encode_base64_unicode` |
| IP fetch fallback chain | ✅ Covered | `test_fetch_ipv4_skips_invalid_then_succeeds` |
| Cache TTL behavior | ❌ Not tested | Would need time mocking |
| Concurrent queries | ❌ Not tested | dnslib handles threading |
| Large payloads (Base64) | ⚠️ Partial | 100-char roundtrip tested |
| Case conversion multi-label | ✅ Covered | `lower.foo.bar` → `FOO.BAR` |

---

## CI/CD Integration

Add to GitHub Actions (`.github/workflows/test.yml`):

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v3
      - run: uv run python -m unittest tests.test_resolver -v
```

---

## Debugging Test Failures

### Verbose output
```bash
python -m unittest tests.test_resolver.TestResolver.test_cidr_resolution -v
```

### Run with debugger
```bash
python -m pdb -m unittest tests.test_resolver.TestResolver.test_cidr_resolution
```

### Common failure patterns

| Error | Likely Cause |
|-------|--------------|
| `AttributeError: 'NoneType' object has no attribute 'rr'` | Matcher returned `None` - check query format |
| `AssertionError: 0 != 1` (len(reply.rr)) | Wrong QTYPE or matcher didn't match |
| `Invalid base64` in test | Test data needs valid padding |
| `ValueError: Prefix must be between 0 and 32` | CIDR test using invalid prefix |

---

## Test Design Principles

1. **Isolate units** - Test matchers/replies separately from full pipeline
2. **Mock externals** - Never hit real network in tests
3. **Test error paths** - Exceptions, fallbacks, empty responses
4. **Check QTYPE handling** - Every feature must reject wrong QTYPE
5. **Use realistic DNS records** - `DNSRecord.question()` creates valid queries