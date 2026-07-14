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
uv run --extra dev pytest
# or
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
| `TestTimeUtils` | `utils/time_utils.py` | Time format, second range, railway→AM/PM conversion (valid + invalid) |
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
@patch("utils.main.fetch_ipv4", return_value="1.2.3.4")
@patch("utils.main.fetch_ipv6", return_value="2001:db8::2")
def test_get_public_ips_fetches_and_caches(self, mock_ipv6, mock_ipv4):
    resolver = Resolver(cache_ttl=60)
    ipv4, ipv6 = resolver._get_public_ips()
    self.assertEqual((ipv4, ipv6), ("1.2.3.4", "2001:db8::2"))
```

**Time module mocking** (for cache TTL tests):
```python
with patch("utils.main.time.time", side_effect=[100.0, 100.0, 102.0, 102.0, 102.0, 102.0]):
    # First fetch at t=100
    self.assertEqual(resolver._get_public_ips(), ("1.1.1.1", "::1"))
    # After TTL at t=102 (cache_time was 100, TTL=1)
    self.assertEqual(resolver._get_public_ips(), ("2.2.2.2", "::2"))
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

## New CLI Tests

### `TestCLI` — Command-line Interface Tests

| Test Method | Coverage |
|-------------|----------|
| `test_cli_current_time` | `--ct` / `--current-time` flag prints current time |
| `test_cli_utilities` | All utility flags: `--cidr`, `--mask`, `--ampm`, `--b64-encode`, `--b64-decode`, `--upper`, `--lower`, `--ip`, `--myip` |

**Pattern**: Uses `argparse.ArgumentParser.parse_args` mocking to simulate CLI arguments, then captures `print()` output.

```python
@patch("utils.main.get_current_time", return_value="2026-07-14 17:50:00")
@patch("argparse.ArgumentParser.parse_args")
def test_cli_current_time(self, mock_parse_args, mock_get_time):
    import argparse
    from utils.main import main
    mock_parse_args.return_value = argparse.Namespace(
        address="127.0.0.1", ct=True, cidr=None, mask=None, ampm=None,
        b64_encode=None, b64_decode=None, upper=None, lower=None, ip=False, myip=False
    )
    with patch("builtins.print") as mock_print:
        main()
        mock_print.assert_called_once_with("2026-07-14 17:50:00")
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