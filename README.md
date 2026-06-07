# compliance-llm-gateway

[![CI](https://github.com/ganeshkm6776/compliance-llm-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/ganeshkm6776/compliance-llm-gateway/actions)
[![PyPI version](https://badge.fury.io/py/compliance-llm-gateway.svg)](https://pypi.org/project/compliance-llm-gateway/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Downloads](https://static.pepy.tech/badge/compliance-llm-gateway)](https://pepy.tech/project/compliance-llm-gateway)

A proxy that sits between your application and LLM APIs (OpenAI, Anthropic, etc.) to enforce regulatory data compliance automatically. Built for banks, healthcare, insurance, and government teams that need to use LLMs without leaking sensitive data.

## The Problem

Your observability data contains PAN numbers, SSNs, PHI, and internal identifiers. You want to send it to an LLM for analysis. Regulations say you can't transmit that data to uncertified third parties. You need a hard boundary between your systems and the LLM provider.

Existing tools like Guardrails AI handle prompt safety (jailbreaks, toxicity). They don't handle regulatory data compliance (PCI DSS, HIPAA, SOX audit trails). This tool does.

## What It Does

```
Your App --> compliance-llm-gateway --> OpenAI/Anthropic/etc.
                    |
                    v
            - Redacts PAN, SSN, PII before prompt leaves your network
            - Logs every interaction to immutable audit trail
            - Enforces prompt version control
            - Switches providers without code changes
            - Blocks prohibited actions structurally
```

## Quick Start

```bash
pip install compliance-llm-gateway
```

```python
from compliance_gateway import Gateway

gw = Gateway(
    provider="openai",
    api_key="sk-...",
    sanitization="strict",  # pci_dss | hipaa | strict
    audit_log="./audit/"
)

# PAN in your data? Automatically redacted before it hits OpenAI.
response = gw.complete(
    prompt="Diagnose this error: Transaction failed for card 4532015112830366 with timeout on service payment-api",
    model="gpt-4"
)

# What OpenAI actually received:
# "Diagnose this error: Transaction failed for card [REDACTED:PAN] with timeout on service payment-api"
```

## Features

**Data Sanitization (4-stage pipeline)**
- Stage 1: Pattern matching with Luhn validation (PAN, SSN, routing numbers)
- Stage 2: Named entity recognition for PII (names, addresses, emails)
- Stage 3: Configurable domain-specific rules (your internal ID formats)
- Stage 4: Conservative fallback (anything uncertain gets redacted)

**Audit Trail**
- Every prompt and response logged with timestamps
- Append-only storage with integrity verification
- Queryable by compliance staff
- Configurable retention (default 7 years for SOX)

**Provider Abstraction**
- Switch between OpenAI, Anthropic, Azure OpenAI, local models via config
- No code changes when switching providers
- Built-in failover between providers
- A/B testing support for model evaluation

**Prompt Governance**
- Prompt templates versioned and tracked
- Change history with diffs
- Approval workflow integration (optional)
- Rollback to any previous version

**Tiered Action Control**
- Tier 1 (autonomous): read-only queries execute without approval
- Tier 2 (human approval): recommendations require human sign-off
- Tier 3 (prohibited): no execution path exists, structurally impossible

## Configuration

```yaml
# gateway.yaml
provider:
  primary: openai
  fallback: anthropic
  timeout: 30s

sanitization:
  mode: strict  # strict | moderate | custom
  stages:
    - pattern_matching: true
    - ner: true
    - domain_rules: ./rules/banking.yaml
    - conservative_fallback: true

audit:
  enabled: true
  storage: ./audit/
  retention_years: 7
  integrity_check: sha256

governance:
  prompt_dir: ./prompts/
  require_approval: false
  track_versions: true
```

## Compliance Modes

| Mode | What It Covers | Use Case |
|------|---------------|----------|
| `pci_dss` | PAN, CVV, cardholder data | Banks, payment processors |
| `hipaa` | PHI, patient identifiers | Healthcare |
| `strict` | All of the above + SSN, financial accounts | Multi-regulation environments |
| `custom` | Your own rules via YAML | Any industry |

## Running as a Proxy

```bash
# Start the gateway as an HTTP proxy
compliance-gateway serve --config gateway.yaml --port 8080

# Your app points to localhost:8080 instead of api.openai.com
# Everything else works the same - the gateway handles sanitization transparently
```

## Running Tests

```bash
pytest tests/ -v

# Run compliance validation specifically
pytest tests/test_sanitization.py -v
pytest tests/test_audit.py -v
```

## Architecture

This implements the reference architecture described in:

> Murugan, G.K. "A Reference Architecture for LLM-Powered Incident Response in Regulated Financial Services." SSRN, 2026.

The gateway is the practical implementation of the "compliance by construction" principle from that paper.

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- Additional sanitization patterns for non-US regulations (GDPR, PSD2)
- Provider adapters (Cohere, Mistral, local ollama)
- Audit storage backends (S3, Azure Blob, database)
- CI/CD integration examples

## License

Apache 2.0