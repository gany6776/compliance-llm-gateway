# compliance-llm-gateway

A Python proxy/library that sits between applications and LLM APIs (OpenAI, Anthropic, etc.) to enforce regulatory data compliance automatically. It sanitizes sensitive data (credit card numbers, SSNs, PII) before prompts reach the LLM provider, logs every interaction to an immutable audit trail, and abstracts the LLM provider for easy switching.

Built for banks, healthcare, insurance, and government teams that need to use LLMs without leaking sensitive data.

> This is the practical implementation of the paper: "A Reference Architecture for LLM-Powered Incident Response in Regulated Financial Services" by Ganesh Kutty Murugan (published on SSRN, 2026).

---

## The Problem

Existing tools like Guardrails AI don't cover regulatory data compliance — they focus on output validation, not on preventing PII/PAN/SSN from reaching the LLM API in the first place. This gateway solves that by sanitizing at the proxy layer before any data leaves your infrastructure.

---

## What It Does

```
User Prompt
    │
    ▼
┌─────────────────────┐
│  Four-Stage         │
│  Sanitizer          │  ◄── PAN, SSN, PII, Auth tokens stripped
└────────┬────────────┘
         │ sanitized prompt
         ▼
┌─────────────────────┐
│  Tier Enforcement   │  ◄── Tier 3 blocked; Tier 1/2 proceed
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  LLM Provider       │  ◄── OpenAI / Anthropic / Azure / Mock
└────────┬────────────┘
         │ response
         ▼
┌─────────────────────┐
│  Immutable Audit    │  ◄── SHA-256 hash chain, JSONL append-only
│  Trail              │
└─────────────────────┘
```

---

## Quick Start

```bash
pip install compliance-llm-gateway
```

```python
from compliance_gateway import Gateway, Sanitizer
from compliance_gateway.providers import OpenAIProvider

gateway = Gateway(
    provider=OpenAIProvider(),
    model="gpt-4",
    tier=1,
)

result = gateway.complete("My card number is 4532015112830366, help me with my account.")
print(result["response"])
# PAN is redacted before reaching OpenAI: [REDACTED:PAN]
```

---

## Features

- **Sanitization** — Four-stage pipeline: Luhn-validated PAN, SSN, CVV, Auth tokens, Email, Phone, IP, domain-specific rules, conservative numeric fallback
- **Audit Trail** — Append-only JSONL with SHA-256 hash chain, queryable by tier/model/date, 7-year default retention
- **Provider Abstraction** — OpenAI, Anthropic, AzureOpenAI, Mock; provider failover built-in
- **Prompt Governance** — Tiered access control (Tier 3 = structurally blocked)
- **Tiered Action Control** — Tier 1 (standard), Tier 2 (elevated), Tier 3 (human review required)

---

## Compliance Modes

| Mode      | Description                                  |
|-----------|----------------------------------------------|
| `strict`  | All stages active, external IPs redacted      |
| `pci_dss` | PAN, CVV, Auth token focus                   |
| `hipaa`   | PHI-oriented redaction                        |
| `moderate`| Reduced strictness, no IP redaction           |

---

## Configuration

```yaml
provider: openai
sanitization:
  mode: strict
  domain_rules:
    ACCOUNT_NUM: '\b(ACCT-\d{8})\b'
    SESSION: '\b(SES-[A-F0-9]{16})\b'
audit:
  path: ./audit
  retention_years: 7
governance:
  default_tier: 1
```

---

## Running as a Proxy (HTTP proxy mode on localhost:8080)

```bash
compliance-gateway sanitize --mode strict
# Reads from stdin, writes sanitized text to stdout
```

---

## Running Tests

```bash
pip install -e ".[dev]"
python -m pytest tests/ -v
```

---

## Architecture

This implementation follows the architecture described in the SSRN paper: "A Reference Architecture for LLM-Powered Incident Response in Regulated Financial Services" (Ganesh Kutty Murugan, 2026).

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0
