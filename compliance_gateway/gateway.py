"""
Main Gateway Orchestrator.
Coordinates: sanitize input -> call LLM -> log to audit.
"""

from typing import Optional, Dict, Any, List

from .sanitizer import Sanitizer
from .audit import AuditLogger
from .providers import BaseProvider, MockProvider


class Gateway:
    """
    The main compliance gateway.

    - Sanitizes prompts before they reach the LLM
    - Enforces tiered access control
    - Logs every interaction to the immutable audit trail
    - Supports provider failover
    """

    def __init__(
        self,
        provider: Optional[BaseProvider] = None,
        fallback_provider: Optional[BaseProvider] = None,
        sanitizer: Optional[Sanitizer] = None,
        audit_logger: Optional[AuditLogger] = None,
        model: str = "gpt-4",
        tier: int = 1,
        prompt_template_version: str = "1.0",
    ):
        self.provider = provider or MockProvider()
        self.fallback_provider = fallback_provider
        self.sanitizer = sanitizer or Sanitizer(mode="strict")
        self.audit_logger = audit_logger or AuditLogger()
        self.model = model
        self.tier = tier
        self.prompt_template_version = prompt_template_version

    def complete(
        self,
        prompt: str,
        metadata: Optional[Dict[str, Any]] = None,
        human_decision: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process a prompt through the compliance gateway.

        Returns dict with keys:
        - response: str
        - redactions: list
        - redaction_count: int
        - audit_hash: str
        - latency_ms: float
        - provider_used: str
        """
        # Tier enforcement: Tier 3 is structurally blocked
        if self.tier >= 3:
            return {
                "response": (
                    "ERROR: Tier 3 requests are blocked. "
                    "Human review required before LLM processing."
                ),
                "redactions": [],
                "redaction_count": 0,
                "audit_hash": None,
                "latency_ms": 0.0,
                "provider_used": None,
            }

        # Sanitize input
        sanitized = self.sanitizer.sanitize(prompt)

        # Call primary provider
        response_data = None
        provider_used = None
        error_msg = None

        try:
            result = self.provider.complete(sanitized.clean_text, model=self.model)
            response_data = result
            provider_used = result.get("provider", "unknown")
        except Exception as e:
            error_msg = str(e)
            # Try fallback provider
            if self.fallback_provider:
                try:
                    result = self.fallback_provider.complete(sanitized.clean_text, model=self.model)
                    response_data = result
                    provider_used = result.get("provider", "fallback")
                except Exception as e2:
                    error_msg = f"Primary: {error_msg}; Fallback: {str(e2)}"

        if response_data is None:
            response_text = (
                "ERROR: All providers failed. Human-only mode required. "
                f"Details: {error_msg}"
            )
            latency_ms = 0.0
        else:
            response_text = response_data.get("response", "")
            latency_ms = response_data.get("latency_ms", 0.0)

        # Log to audit trail
        audit_hash = self.audit_logger.log(
            prompt_sanitized=sanitized.clean_text,
            response=response_text,
            redactions=sanitized.redactions,
            redaction_count=len(sanitized.redactions),
            latency_ms=latency_ms,
            model=self.model,
            provider=provider_used or "none",
            tier=self.tier,
            prompt_template_version=self.prompt_template_version,
            human_decision=human_decision,
            metadata=metadata,
        )

        return {
            "response": response_text,
            "redactions": sanitized.redactions,
            "redaction_count": len(sanitized.redactions),
            "audit_hash": audit_hash,
            "latency_ms": latency_ms,
            "provider_used": provider_used,
        }

    def sanitize_only(self, text: str) -> Dict[str, Any]:
        """Sanitize text without making any LLM calls (for testing)."""
        result = self.sanitizer.sanitize(text)
        return {
            "clean_text": result.clean_text,
            "redactions": result.redactions,
            "redaction_count": len(result.redactions),
            "original_length": result.original_length,
            "redacted_length": result.redacted_length,
        }

    def verify_audit_chain(self) -> Dict[str, Any]:
        """Verify the integrity of the audit chain."""
        return self.audit_logger.verify_chain()

    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit statistics for compliance dashboards."""
        return self.audit_logger.get_stats()
