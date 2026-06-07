# Frequently Asked Questions

## General

### What is compliance-llm-gateway?

A Python library that acts as a proxy between your application and LLM providers (OpenAI, Anthropic, Azure). It automatically strips sensitive data from prompts before they leave your network, logs every interaction to a tamper-evident audit trail, and lets you swap providers without changing application code.

### Who is this for?

Engineering teams at banks, insurers, healthcare organizations, and government agencies that want to use LLMs but can't because of regulatory requirements around data handling. If your compliance team has blocked LLM adoption due to PCI DSS, HIPAA, SOX, or SR 11-7 concerns, this library addresses those objections directly.

### How is this different from Guardrails AI or similar tools?

Guardrails AI focuses on output validation (making sure the LLM gives you structured, correct responses). This gateway focuses on input sanitization (making sure sensitive data never reaches the LLM in the first place). Different problems entirely. You could use both together - this gateway sanitizes the prompt, Guardrails validates the response.

### Does this replace my DLP (Data Loss Prevention) tool?

No. DLP tools monitor network traffic broadly. This library operates at the application layer, specifically for LLM API calls. Think of it as a specialized DLP for the LLM pathway. Your network DLP should still be in place as defense-in-depth.

---

## Installation and Setup

### What are the dependencies?

Zero required dependencies. The core sanitization and audit trail use only Python standard library modules (`re`, `json`, `hashlib`, `dataclasses`). Provider SDKs are optional:

```bash
pip install compliance-llm-gateway              # Core only
pip install compliance-llm-gateway[openai]      # + OpenAI SDK
pip install compliance-llm-gateway[anthropic]   # + Anthropic SDK
pip install compliance-llm-gateway[all]         # All providers
```

### What Python versions are supported?

Python 3.9 and above. Tested on 3.9, 3.10, 3.11, and 3.12 via GitHub Actions CI.

### How do I configure the provider API keys?

Set environment variables. The gateway reads them automatically:

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
export AZURE_OPENAI_API_VERSION="2024-02-01"
```

### Can I use this without any LLM provider configured?

Yes. Use `sanitize_only()` to run the sanitization pipeline without making an API call:

```python
from compliance_gateway import Gateway

gw = Gateway(provider="mock")
result = gw.sanitize_only("Card 4532015112830366 reported stolen")
print(result.clean_text)  # "Card [REDACTED:PAN] reported stolen"
```

Also useful for testing and validation before going live.

---

## Sanitization

### What data types does it catch?

| Stage | Data Types |
|-------|-----------|
| 1 | Credit card numbers (Visa, Mastercard, AMEX), SSNs, CVVs, Bearer tokens, JWTs, OpenAI API keys, Slack tokens, routing numbers |
| 2 | Email addresses, phone numbers, external IP addresses (strict mode) |
| 3 | Whatever custom patterns you configure |
| 4 | Any numeric sequence of 10+ digits not caught above |

### What is Luhn validation and why does it matter?

The Luhn algorithm is a checksum formula used to validate credit card numbers. Not every 16-digit number is a credit card. Order IDs, timestamps concatenated together, database row IDs - many things happen to be 16 digits.

Without Luhn: `1234567890123456` gets redacted (false positive).
With Luhn: `1234567890123456` fails the checksum, stays in the prompt. Only numbers that pass the checksum (structurally valid card numbers) get redacted.

This reduces false positives dramatically while maintaining zero false negatives for real card numbers.

### Why aren't internal IPs redacted?

Internal/private IP addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x) are useless outside your network. They can't identify a customer or expose infrastructure to the public internet. But they're critical for the LLM to diagnose network issues, routing problems, and service connectivity. Redacting them would make the LLM's response useless for infrastructure troubleshooting.

External/public IPs can reveal server locations, cloud provider details, and network topology. Those get redacted in strict mode.

### What happens when the sanitizer isn't sure?

It redacts. The pipeline is biased toward over-redaction (false positives) rather than under-redaction (data leaks). A false positive means the LLM sees `[REDACTED:NUMERIC_ID]` instead of a harmless reference number - the response might be slightly less specific. A false negative means customer PII reaches a third-party API. The cost asymmetry is obvious.

### Can I add my own patterns?

Yes. Stage 3 accepts a dictionary of custom rules:

```python
from compliance_gateway import Sanitizer

rules = {
    "ACCOUNT_NUM": r'\b(ACCT-\d{8})\b',
    "LOAN_ID": r'\b(LN-\d{10})\b',
    "MEMBER_ID": r'\b(MBR-[A-Z]{2}\d{6})\b'
}

s = Sanitizer(domain_rules=rules)
result = s.sanitize("Account ACCT-12345678 has loan LN-0099887766")
# "Account [REDACTED:ACCOUNT_NUM] has loan [REDACTED:LOAN_ID]"
```

### What are the compliance modes?

| Mode | Behavior |
|------|----------|
| `strict` | All 4 stages active, external IPs redacted, most aggressive |
| `pci_dss` | Focus on cardholder data (PANs, CVVs, auth tokens) |
| `hipaa` | Focus on PHI identifiers (names, emails, phones, dates, IDs) |
| `moderate` | Stages 1-3 only, no conservative fallback |

### Does redaction break the LLM's ability to help?

Rarely. The gateway preserves all surrounding context. The LLM sees:

```
"Customer [REDACTED:EMAIL] reported timeout on card [REDACTED:PAN] at 02:14 UTC"
```

It still knows: a customer reported a timeout, it involved a card transaction, it happened at 02:14 UTC. That's enough to diagnose most issues. The actual card number doesn't help the LLM debug a timeout.

For the rare case where the actual value matters (comparing two account numbers for a routing issue), you'd handle that logic in your application code, not in an LLM prompt.

### What about names? Does it catch "John Smith"?

The current version doesn't do named entity recognition for person names. Names are hard - "Chase" is both a name and a bank, "Wells" is both a name and part of "Wells Fargo." False positives on names destroy prompt readability.

If your use case requires name redaction, add a domain rule with your customer name format, or contribute a name detection module to the project.

---

## Audit Trail

### How does the audit trail work?

Every LLM interaction gets logged to an append-only JSONL file (one file per day, named `audit_YYYY-MM-DD.jsonl`). Each record contains a SHA-256 hash of its contents plus the previous record's hash, forming a chain. If anyone modifies, deletes, or reorders a record, the chain breaks.

### What gets logged?

Each record contains:
- Timestamp
- The sanitized prompt (never the original with PII)
- Model and provider used
- LLM response
- List of redactions (type, stage, position)
- Redaction count
- Latency in milliseconds
- Tier level
- SHA-256 hash of the record
- Previous record's hash (chain link)

### Can someone tamper with the audit logs?

They can modify the file on disk, but they can't do it without breaking the hash chain. Running `verify_chain()` detects any tampering:

```python
integrity = gw.verify_audit_chain()
# {"status": "valid", "records_checked": 1247}
# or
# {"status": "invalid", "broken_at_record": 843, "expected_hash": "a3f2...", "actual_hash": "7b9c..."}
```

For production, ship the audit files to immutable storage (S3 with object lock, WORM storage) as an additional layer.

### How long are logs retained?

Default is 7 years, matching PCI DSS and SOX retention requirements. Configurable if your regulations specify differently.

### Can I query the audit trail?

Yes. Filter by date range, model, tier, or any field:

```python
# All Tier 2 interactions using GPT-4 in January
records = gw.query_audit(tier=2, model="gpt-4", start="2026-01-01", end="2026-01-31")
```

CLI equivalent:
```bash
compliance-gateway audit query --tier 2 --model gpt-4 --start 2026-01-01
```

### What do I show an auditor?

Run `get_audit_stats()` for a summary (total interactions, redaction counts by type, tier distribution). Run `verify_audit_chain()` to prove integrity. Both are available via CLI:

```bash
compliance-gateway audit stats --audit-path ./audit/
compliance-gateway audit verify --audit-path ./audit/
```

---

## Provider Abstraction

### Which LLM providers are supported?

- OpenAI (GPT-4, GPT-3.5, etc.)
- Anthropic (Claude 3, Claude 4)
- Azure OpenAI (enterprise deployments)
- Mock provider (for testing without API calls)

### How do I switch providers?

Change one parameter:

```python
# Before
gw = Gateway(provider="openai")

# After
gw = Gateway(provider="anthropic")
```

No other code changes needed. The sanitization, audit trail, and response format stay identical.

### What happens if the LLM provider is down?

If you configure a fallback provider, the gateway tries it automatically:

```python
gw = Gateway(provider="openai", fallback_provider="anthropic")
result = gw.complete(prompt)
# If OpenAI times out, Anthropic handles it
# result.provider_used tells you which one responded
```

If both fail, you get an error response indicating "human-only mode" - the request needs manual handling.

### Can I use a self-hosted model (Ollama, vLLM)?

Not yet in v0.1.0. Provider contributions for Ollama, Cohere, and Mistral are on the roadmap. The `BaseProvider` class makes adding new providers straightforward - implement a single `complete()` method.

---

## Tiered Action Control

### What are tiers?

A classification system for prompt risk levels:

| Tier | Description | Gateway Behavior |
|------|-------------|-----------------|
| 1 | Low risk (diagnostics, log analysis) | Sanitize and send to LLM |
| 2 | Medium risk (customer-facing suggestions) | Sanitize, send, flag for review |
| 3 | High risk (decisions requiring human judgment) | Structurally blocked, no API call made |

### What does "structurally blocked" mean?

Tier 3 prompts never reach the LLM API. The gateway returns an error immediately without making a network call. The block is architectural, not policy-based. Even if someone bypasses the configuration, the code path physically doesn't call the provider.

Use this for scenarios where regulations require human decision-makers regardless of AI capability: customer termination decisions, credit limit changes, fraud determination letters.

### Who decides the tier?

Your application code sets it per request:

```python
# SRE diagnosing an outage - Tier 1, send it
result = gw.complete("Why is the payment service timing out?", tier=1)

# Generating a customer-facing explanation - Tier 2, send but flag
result = gw.complete("Draft an explanation for the outage", tier=2)

# Making a credit decision - Tier 3, blocked
result = gw.complete("Should we close this customer's account?", tier=3)
```

---

## Integration

### How do I integrate with an existing application?

Three lines:

```python
from compliance_gateway import Gateway

gw = Gateway(provider="openai", mode="pci_dss", audit_path="./audit/")

# Replace your direct OpenAI call with this
result = gw.complete(user_prompt)
```

### Can I use it as a CLI tool?

Yes. Pipe text through the sanitizer without writing Python:

```bash
echo "Card 4532015112830366 failed" | compliance-gateway sanitize --mode strict
# Output: Card [REDACTED:PAN] failed
# Stderr: Redactions: 1 (PAN: 1)
```

### Can I run it as an HTTP proxy?

Proxy mode is on the roadmap for v0.2.0. Currently it operates as a library you import. For HTTP proxy behavior today, wrap it in a FastAPI/Flask endpoint:

```python
from fastapi import FastAPI
from compliance_gateway import Gateway

app = FastAPI()
gw = Gateway(provider="openai")

@app.post("/v1/complete")
async def complete(prompt: str):
    result = gw.complete(prompt)
    return {"response": result.response, "redactions": result.redaction_count}
```

### Does it work with LangChain or LlamaIndex?

Not natively integrated yet, but you can wrap it. Sanitize before passing to LangChain:

```python
from compliance_gateway import Sanitizer

s = Sanitizer(mode="strict")
result = s.sanitize(user_input)
# Pass result.clean_text to your LangChain chain
```

---

## Performance

### How much latency does the sanitizer add?

Typical sanitization takes 1-5ms for prompts under 4000 tokens. The regex operations and Luhn checks are computationally trivial. Your LLM API call (500-5000ms) dominates total latency by two orders of magnitude.

### Does it work with streaming responses?

The sanitization applies to the outbound prompt, not the response stream. LLM responses stream back normally. The audit log captures the full response after streaming completes.

### Is there a prompt size limit?

No hard limit from the gateway. Your LLM provider's context window is the constraint. The sanitizer processes text sequentially and handles any length.

---

## Security

### Does the gateway store the original unsanitized text?

No. The original text exists only in memory during processing. The audit trail stores only the sanitized version. Once `sanitize()` returns, the original is eligible for garbage collection. No disk write of raw PII occurs.

### What if someone passes the redaction placeholder as input?

If someone sends `"My card is [REDACTED:PAN]"` as input, it passes through unchanged. The placeholders are output-only markers. The gateway doesn't confuse them with actual redactions.

### Can the LLM reconstruct redacted data?

No. The LLM receives `[REDACTED:PAN]` - it has no information about what the original value was. There's nothing to reconstruct. The gateway doesn't send a mapping table or reversible tokens.

### What about prompt injection attacks?

The gateway sanitizes data, it doesn't validate prompt intent. For prompt injection defense, use it alongside output validation tools (Guardrails AI, custom validators). The gateway ensures that even if a prompt injection succeeds, no sensitive data was in the prompt to exfiltrate.

---

## Compliance Specifics

### Does this make me PCI DSS compliant?

It addresses a specific PCI DSS requirement: cardholder data must not be transmitted to unauthorized systems. The gateway ensures PANs, CVVs, and auth data never reach the LLM provider. But PCI DSS compliance involves dozens of requirements beyond data transmission. This is one control in your overall compliance program.

### How does this help with SOX audits?

SOX requires demonstrable controls over financial data handling and an audit trail showing who accessed what. The hash-chained audit log provides tamper-evident proof of every LLM interaction, what data was redacted, and when.

### Does the audit trail satisfy SR 11-7 (model risk management)?

SR 11-7 requires documentation of model inputs, outputs, and performance monitoring. The audit trail captures all of these per interaction. Combined with the redaction reports, you can demonstrate to examiners that model inputs are controlled and logged.

### Can I use this for GDPR compliance?

The current redaction patterns focus on US financial data (PAN, SSN, US phone formats). GDPR patterns (EU national IDs, IBAN numbers, EU phone formats, addresses) are on the roadmap. You can add EU-specific patterns today via Stage 3 domain rules:

```python
rules = {
    "IBAN": r'\b([A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16})\b',
    "EU_PHONE": r'\b(\+?3[0-9]\d{8,11})\b'
}
s = Sanitizer(domain_rules=rules)
```

---

## Troubleshooting

### The sanitizer is redacting things it shouldn't (false positives)

Check which stage caught it:

```python
result = s.sanitize(text)
for r in result.redactions:
    print(f"Type: {r['type']}, Stage: {r['stage']}, Position: {r['position']}")
```

If Stage 4 is catching your internal reference numbers, you have two options:
1. Switch to `moderate` mode (disables Stage 4 fallback)
2. Make the reference number shorter than 10 digits if possible

If Stage 1 catches a number that passes Luhn by coincidence, that's extremely rare (1 in 10 chance for any random 16-digit number). Consider shortening or reformatting the identifier.

### The sanitizer missed something it should have caught

Check the mode. IP addresses only get redacted in `strict` mode. Phone numbers need to match US format. If your data has a unique format, add it as a Stage 3 domain rule.

### Tests are failing after I added custom rules

Make sure your regex uses raw strings (`r'...'`) and includes capture groups `()` around the part you want redacted. The gateway replaces the full match including the capture group.

### The audit chain verification failed

Something modified an audit file. Check:
1. File permissions - ensure no other process writes to the audit directory
2. Line endings - if you opened the file in an editor that changed CRLF/LF, the hash changes
3. Disk corruption - compare against your backup copy

The broken record number tells you exactly where the chain diverges.

---

## Contributing

### How do I add a new provider?

Implement the `BaseProvider` class with a `complete()` method:

```python
class MyProvider(BaseProvider):
    def complete(self, prompt: str, model: str = None, **kwargs) -> str:
        # Call your LLM API here
        return response_text
```

Register it in the `get_provider()` factory function. Submit a PR with tests.

### What contributions are most needed?

1. GDPR redaction patterns (EU national IDs, IBAN, EU phone formats)
2. Additional providers (Ollama, Cohere, Mistral, Bedrock)
3. Audit backends (S3 with object lock, Azure Blob, PostgreSQL)
4. Performance benchmarks with large prompts
5. Integration guides for LangChain, LlamaIndex, Semantic Kernel

### How do I run the test suite?

```bash
git clone https://github.com/gany6776/compliance-llm-gateway.git
cd compliance-llm-gateway
pip install -e ".[dev]"
pytest tests/ -v
```

All 32 tests should pass. If adding a feature, add corresponding tests.