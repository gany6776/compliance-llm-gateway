"""
test_audit.py - 7 tests for the immutable audit trail.
"""

import pytest

from compliance_gateway.audit import AuditLogger


@pytest.fixture
def tmp_audit(tmp_path):
    """Provide a fresh AuditLogger backed by a temp directory."""
    return AuditLogger(audit_path=str(tmp_path))


class TestAuditLogging:

    def test_log_creates_record(self, tmp_audit):
        record_hash = tmp_audit.log(
            prompt_sanitized="Hello",
            response="Hi there",
            redactions=[],
            redaction_count=0,
            latency_ms=42.0,
            model="gpt-4",
            provider="openai",
            tier=1,
        )
        assert isinstance(record_hash, str)
        assert len(record_hash) == 64  # SHA-256 hex

    def test_multiple_records_chained(self, tmp_audit):
        hash1 = tmp_audit.log(
            prompt_sanitized="First",
            response="Response 1",
            redactions=[],
            redaction_count=0,
            latency_ms=10.0,
            model="gpt-4",
            provider="openai",
            tier=1,
        )
        hash2 = tmp_audit.log(
            prompt_sanitized="Second",
            response="Response 2",
            redactions=[],
            redaction_count=0,
            latency_ms=20.0,
            model="gpt-4",
            provider="openai",
            tier=1,
        )
        assert hash1 != hash2

    def test_chain_verification_passes(self, tmp_audit):
        for i in range(5):
            tmp_audit.log(
                prompt_sanitized=f"Prompt {i}",
                response=f"Response {i}",
                redactions=[],
                redaction_count=0,
                latency_ms=float(i * 10),
                model="claude-3",
                provider="anthropic",
                tier=1,
            )
        result = tmp_audit.verify_chain()
        assert result["status"] == "valid"


class TestAuditQuery:

    def test_query_by_tier(self, tmp_audit):
        tmp_audit.log("p1", "r1", [], 0, 10.0, "gpt-4", "openai", tier=1)
        tmp_audit.log("p2", "r2", [], 0, 10.0, "gpt-4", "openai", tier=2)
        tmp_audit.log("p3", "r3", [], 0, 10.0, "gpt-4", "openai", tier=2)
        records = tmp_audit.query(tier=2)
        assert len(records) == 2
        assert all(r["tier"] == 2 for r in records)

    def test_query_by_model(self, tmp_audit):
        tmp_audit.log("p1", "r1", [], 0, 10.0, "claude-3", "anthropic", tier=1)
        tmp_audit.log("p2", "r2", [], 0, 10.0, "gpt-4", "openai", tier=1)
        records = tmp_audit.query(model="claude-3")
        assert len(records) == 1
        assert records[0]["model"] == "claude-3"


class TestAuditStats:

    def test_stats_empty(self, tmp_audit):
        stats = tmp_audit.get_stats()
        assert stats["total_interactions"] == 0

    def test_stats_with_records(self, tmp_audit):
        tmp_audit.log("p1", "r1", [{"type": "PAN"}], 1, 10.0, "gpt-4", "openai", tier=1)
        tmp_audit.log("p2", "r2", [{"type": "SSN"}, {"type": "EMAIL"}], 2, 20.0, "gpt-4", "openai", tier=2)
        tmp_audit.log("p3", "r3", [], 0, 5.0, "claude-3", "anthropic", tier=1)
        stats = tmp_audit.get_stats()
        assert stats["total_interactions"] == 3
        assert stats["total_redactions"] == 3
        assert stats["tier_distribution"][1] == 2
        assert stats["tier_distribution"][2] == 1
