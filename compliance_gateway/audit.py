"""
Immutable Audit Trail with SHA-256 hash chain.
Append-only JSONL storage with chain verification and query support.
"""

import hashlib
import json
from datetime import datetime, date
from pathlib import Path
from typing import Optional, Dict, Any, List


class AuditLogger:
    """
    Append-only audit logger with SHA-256 hash chaining.

    - One JSONL file per day: audit_YYYY-MM-DD.jsonl
    - Each record contains prev_hash and computed record_hash
    - Default 7-year retention
    - Queryable by date range, model, tier
    - Stats endpoint for compliance dashboards
    """

    RETENTION_YEARS = 7

    def __init__(self, audit_path: str = "./audit"):
        self.audit_path = Path(audit_path)
        self.audit_path.mkdir(parents=True, exist_ok=True)
        self._prev_hash: Optional[str] = self._load_last_hash()

    def _today_file(self) -> Path:
        today = date.today().strftime("%Y-%m-%d")
        return self.audit_path / f"audit_{today}.jsonl"

    def _load_last_hash(self) -> Optional[str]:
        """Load the last record_hash from the most recent audit file."""
        files = sorted(self.audit_path.glob("audit_*.jsonl"), reverse=True)
        for f in files:
            try:
                lines = f.read_text(encoding="utf-8").strip().splitlines()
                if lines:
                    last = json.loads(lines[-1])
                    return last.get("record_hash")
            except Exception:
                continue
        return None

    def _compute_hash(self, record: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of a record (excluding record_hash field)."""
        record_copy = {k: v for k, v in record.items() if k != "record_hash"}
        serialized = json.dumps(record_copy, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def log(
        self,
        prompt_sanitized: str,
        response: str,
        redactions: list,
        redaction_count: int,
        latency_ms: float,
        model: str,
        provider: str,
        tier: int,
        prompt_template_version: str = "1.0",
        human_decision: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Log an interaction to the audit trail.
        Returns the record_hash (64-char SHA-256).
        """
        record = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "prev_hash": self._prev_hash,
            "prompt_sanitized": prompt_sanitized,
            "prompt_template_version": prompt_template_version,
            "model": model,
            "provider": provider,
            "response": response,
            "redactions": redactions,
            "redaction_count": redaction_count,
            "latency_ms": latency_ms,
            "tier": tier,
            "human_decision": human_decision,
            "metadata": metadata or {},
        }
        record_hash = self._compute_hash(record)
        record["record_hash"] = record_hash

        audit_file = self._today_file()
        with audit_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

        self._prev_hash = record_hash
        return record_hash

    def verify_chain(self, audit_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Verify the integrity of the audit chain across all files.
        Returns {"status": "valid"} or {"status": "invalid", "error": ...}
        """
        path = Path(audit_path) if audit_path else self.audit_path
        files = sorted(path.glob("audit_*.jsonl"))
        prev_hash = None
        total = 0

        for f in files:
            try:
                lines = f.read_text(encoding="utf-8").strip().splitlines()
                for line in lines:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if record.get("prev_hash") != prev_hash:
                        return {
                            "status": "invalid",
                            "error": f"Chain broken at record {total + 1} in {f.name}",
                        }
                    stored_hash = record.get("record_hash")
                    computed = self._compute_hash(record)
                    if computed != stored_hash:
                        return {
                            "status": "invalid",
                            "error": f"Hash mismatch at record {total + 1} in {f.name}",
                        }
                    prev_hash = stored_hash
                    total += 1
            except Exception as e:
                return {"status": "invalid", "error": str(e)}

        return {"status": "valid", "total_records": total}

    def query(
        self,
        tier: Optional[int] = None,
        model: Optional[str] = None,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        audit_path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query audit records with optional filters."""
        path = Path(audit_path) if audit_path else self.audit_path
        results = []

        files = sorted(path.glob("audit_*.jsonl"))
        for f in files:
            # Filter by date range using filename
            if start_date and f.stem.replace("audit_", "") < start_date:
                continue
            if end_date and f.stem.replace("audit_", "") > end_date:
                continue
            try:
                lines = f.read_text(encoding="utf-8").strip().splitlines()
                for line in lines:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    if tier is not None and record.get("tier") != tier:
                        continue
                    if model is not None and record.get("model") != model:
                        continue
                    results.append(record)
            except Exception:
                continue

        return results

    def get_stats(self, audit_path: Optional[str] = None) -> Dict[str, Any]:
        """Return aggregate statistics for compliance dashboards."""
        path = Path(audit_path) if audit_path else self.audit_path
        total_interactions = 0
        total_redactions = 0
        tier_distribution: Dict[int, int] = {}
        model_counts: Dict[str, int] = {}

        files = sorted(path.glob("audit_*.jsonl"))
        for f in files:
            try:
                lines = f.read_text(encoding="utf-8").strip().splitlines()
                for line in lines:
                    if not line.strip():
                        continue
                    record = json.loads(line)
                    total_interactions += 1
                    total_redactions += record.get("redaction_count", 0)
                    tier = record.get("tier")
                    if tier is not None:
                        tier_distribution[tier] = tier_distribution.get(tier, 0) + 1
                    mdl = record.get("model", "unknown")
                    model_counts[mdl] = model_counts.get(mdl, 0) + 1
            except Exception:
                continue

        return {
            "total_interactions": total_interactions,
            "total_redactions": total_redactions,
            "tier_distribution": tier_distribution,
            "model_counts": model_counts,
        }
