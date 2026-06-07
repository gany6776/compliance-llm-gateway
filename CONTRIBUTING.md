# Contributing to compliance-llm-gateway

Thank you for your interest in contributing!

## Workflow

- Fork + branch + test + PR workflow
- All PRs must pass the full test suite (32 tests)

## Dev Setup

```bash
git clone https://github.com/ganesh6776/compliance-llm-gateway.git
cd compliance-llm-gateway
pip install -e ".[dev]"
pytest
```

## Commit Format

Use conventional commit format:

```
feat: add Mistral provider support
fix: correct Luhn edge case for AMEX
docs: update README proxy diagram
test: add stage 3 domain rule tests
```

## Priority Areas

- GDPR patterns (EU-specific PII)
- More providers: Cohere, Mistral, Ollama
- Audit backends: S3, Azure Blob, PostgreSQL
- Benchmarks for sanitization throughput

## Code Style

Formatted with `ruff` (line-length = 100, target = py39).

```bash
ruff check .
ruff format .
```
