# Test Scenarios for compliance-llm-gateway

After installing via `pip install compliance-llm-gateway`, use these scenarios to verify the package works correctly.

---

## 1. Quick Smoke Test

```cmd
python -c "from compliance_gateway import Gateway, Sanitizer, AuditLogger; print('Import successful')"
```

Expected output:
```
Import successful
```

---

## 2. Credit Card (PAN) Redaction

```cmd
python -c "from compliance_gateway import Sanitizer; s = Sanitizer(mode='strict'); result = s.sanitize('Customer card 4532015112830366 was declined'); print('Output:', result.clean_text); print('Redactions:', len(result.redactions))"
```

Expected output:
```
Output: Customer card [REDACTED:PAN] was declined
Redactions: 1
```

---

## 3. Mixed PII Redaction

```cmd
python -c "from compliance_gateway import Sanitizer; s = Sanitizer(mode='strict'); result = s.sanitize('John (john@bank.com, SSN 123-45-6789) called about card 5425233430109903. Ref: 98765432101234'); print('Output:', result.clean_text); print('Redactions:', len(result.redactions))"
```

Expected output:
```
Output: John ([REDACTED:EMAIL], SSN [REDACTED:SSN]) called about card [REDACTED:PAN]. Ref: [REDACTED:NUMERIC_ID]
Redactions: 4
```

---

## 4. CLI Pipe Test

```cmd
echo Card 4532015112830366 and SSN 123-45-6789 | compliance-gateway sanitize --mode strict
```

Expected output:
```
Card [REDACTED:PAN] and SSN [REDACTED:SSN]
```

---

## 5. Luhn Validation (False Positive Prevention)

```cmd
python -c "from compliance_gateway import Sanitizer; s = Sanitizer(); result = s.sanitize('Order ID: 1234567890123456'); print('Output:', result.clean_text); print('PAN redacted:', '[REDACTED:PAN]' in result.clean_text)"
```

Expected output:
```
Output: Order ID: 1234567890123456
PAN redacted: False
```

The 16-digit number fails Luhn checksum, so it is not treated as a credit card.

---

## 6. Internal IP Not Redacted

```cmd
python -c "from compliance_gateway import Sanitizer; s = Sanitizer(mode='strict'); result = s.sanitize('Server 10.0.1.55 is healthy, but 52.14.233.100 is down'); print('Output:', result.clean_text)"
```

Expected output:
```
Output: Server 10.0.1.55 is healthy, but [REDACTED:IP] is down
```

Internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x) are preserved. External IPs are redacted in strict mode.

---

## 7. Custom Domain Rules

```cmd
python -c "from compliance_gateway import Sanitizer; rules = {'ACCOUNT_NUM': r'\b(ACCT-\d{8})\b', 'LOAN_ID': r'\b(LN-\d{10})\b'}; s = Sanitizer(domain_rules=rules); result = s.sanitize('Account ACCT-12345678 has loan LN-0099887766'); print('Output:', result.clean_text); print('Redactions:', len(result.redactions))"
```

Expected output:
```
Output: Account [REDACTED:ACCOUNT_NUM] has loan [REDACTED:LOAN_ID]
Redactions: 2
```

---

## 8. SSN Validation Rules

```cmd
python -c "from compliance_gateway import Sanitizer; s = Sanitizer(); valid = s.sanitize('SSN: 123-45-6789'); invalid = s.sanitize('Number: 000-12-3456'); print('Valid SSN redacted:', '[REDACTED:SSN]' in valid.clean_text); print('Invalid SSN (area 000) redacted:', '[REDACTED:SSN]' in invalid.clean_text)"
```

Expected output:
```
Valid SSN redacted: True
Invalid SSN (area 000) redacted: False
```

SSNs with area=000, area=666, or area>=900 are not valid and are left alone.

---

## 9. Auth Token Detection

```cmd
python -c "from compliance_gateway import Sanitizer; s = Sanitizer(); result = s.sanitize('API key: sk-abc123def456ghi789jkl012mno345'); print('Output:', result.clean_text)"
```

Expected output:
```
Output: API key: [REDACTED:AUTH_TOKEN]
```

Catches Bearer tokens, JWTs, OpenAI sk- keys, and Slack xox tokens.

---

## 10. Full Integration Test Script

Save as `test_quick.py` and run with `python test_quick.py`:

```python
from compliance_gateway import Sanitizer, AuditLogger
import tempfile

print("=" * 60)
print("COMPLIANCE LLM GATEWAY - INTEGRATION TEST")
print("=" * 60)

# Test 1: Sanitizer with mixed data
print("\n--- Test 1: Mixed PII Sanitization ---")
s = Sanitizer(mode="strict")
text = (
    "Customer John (john@bank.com, SSN 123-45-6789) called about "
    "failed transaction on card 4532015112830366. "
    "Server 10.0.1.55 returned 500. External IP: 52.14.233.100. "
    "Internal ref: 98765432101234"
)
result = s.sanitize(text)
print(f"Input:  {text}")
print(f"Output: {result.clean_text}")
print(f"Redactions: {len(result.redactions)}")
for r in result.redactions:
    print(f"  Stage {r['stage']}: {r['type']}")

# Test 2: Clean text passes through
print("\n--- Test 2: Clean Text (No Redaction) ---")
clean = "The payment-api service returned HTTP 500 at 14:32 UTC"
result = s.sanitize(clean)
print(f"Input:  {clean}")
print(f"Output: {result.clean_text}")
print(f"Redactions: {len(result.redactions)}")
assert result.clean_text == clean, "FAIL: clean text was modified"
print("PASS: text unchanged")

# Test 3: Luhn validation prevents false positives
print("\n--- Test 3: Luhn Validation ---")
result = s.sanitize("Order 1234567890123456 confirmed")
assert "[REDACTED:PAN]" not in result.clean_text, "FAIL: invalid Luhn was redacted"
print("PASS: invalid Luhn number not redacted")

# Test 4: Custom domain rules
print("\n--- Test 4: Domain-Specific Rules ---")
rules = {"ACCOUNT_NUM": r"\b(ACCT-\d{8})\b", "SESSION": r"\b(SES-[A-F0-9]{16})\b"}
s2 = Sanitizer(domain_rules=rules)
result = s2.sanitize("Account ACCT-12345678, session SES-AB12CD34EF560A78")
print(f"Output: {result.clean_text}")
assert "[REDACTED:ACCOUNT_NUM]" in result.clean_text, "FAIL: account not redacted"
assert "[REDACTED:SESSION]" in result.clean_text, "FAIL: session not redacted"
print("PASS: custom rules applied")

# Test 5: Audit trail
print("\n--- Test 5: Audit Trail ---")
audit_path = tempfile.mkdtemp()
logger = AuditLogger(audit_path=audit_path)

h1 = logger.log(
    prompt_sanitized="What caused timeout on [REDACTED:PAN]?",
    model="gpt-4",
    provider="openai",
    response="Check connection pool exhaustion",
    redactions=[{"type": "PAN", "stage": 1}],
    redaction_count=1,
    latency_ms=1200,
    tier=1,
)
h2 = logger.log(
    prompt_sanitized="Draft response for [REDACTED:EMAIL]",
    model="gpt-4",
    provider="openai",
    response="Dear customer, we apologize...",
    redactions=[{"type": "EMAIL", "stage": 2}],
    redaction_count=1,
    latency_ms=900,
    tier=2,
)

print(f"Record 1 hash: {h1[:16]}...")
print(f"Record 2 hash: {h2[:16]}...")
assert h1 != h2, "FAIL: hashes should differ"
assert len(h1) == 64, "FAIL: hash should be 64 chars (SHA-256)"
print("PASS: records created with unique hashes")

# Verify chain
integrity = logger.verify_chain()
print(f"Chain status: {integrity['status']}")
assert integrity["status"] == "valid", "FAIL: chain should be valid"
print("PASS: chain integrity verified")

# Stats
stats = logger.get_stats()
print(f"Total interactions: {stats['total_interactions']}")
assert stats["total_interactions"] == 2, "FAIL: should have 2 records"
print("PASS: stats correct")

# Test 6: Zero leakage test
print("\n--- Test 6: Zero Leakage (Critical Compliance) ---")
s3 = Sanitizer()
test_pans = [
    "4532015112830366",
    "5425233430109903",
    "371449635398431",
    "4532 0151 1283 0366",
    "5425-2334-3010-9903",
]
leaked = 0
for pan in test_pans:
    result = s3.sanitize(f"Error on card {pan} in service xyz")
    digits = pan.replace(" ", "").replace("-", "")
    if digits in result.clean_text.replace(" ", ""):
        leaked += 1
        print(f"  LEAKED: {pan}")

print(f"Leakage rate: {leaked}/{len(test_pans)}")
assert leaked == 0, "FAIL: PAN data leaked through sanitizer"
print("PASS: 0% leakage - all PANs redacted")

# Summary
print("\n" + "=" * 60)
print("ALL TESTS PASSED")
print("=" * 60)
```

---

## 11. Run the Full Test Suite

```cmd
cd compliance-llm-gateway
pip install pytest
pytest tests/ -v
```

Expected: all 32 tests pass.

---

## Expected Results Summary

| Test | What It Proves |
|------|---------------|
| Smoke test | Package installed correctly |
| PAN redaction | Luhn-validated credit card detection works |
| Mixed PII | All 4 stages run in sequence |
| CLI pipe | Command-line interface works |
| Luhn validation | False positives prevented |
| Internal IP | Private ranges preserved for debugging |
| Domain rules | Custom patterns configurable |
| SSN validation | Area/group/serial rules enforced |
| Auth tokens | API keys and JWTs caught |
| Integration script | Full pipeline including audit trail |
| Zero leakage | Critical compliance: no PAN escapes |
| Test suite | All 32 unit tests pass |