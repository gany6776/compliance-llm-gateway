"""
Four-Stage Data Sanitization Pipeline for regulatory compliance.
Sanitizes sensitive data (PAN, SSN, PII) before it reaches LLM providers.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Optional


@dataclass
class RedactionResult:
    original_length: int
    redactions: list = field(default_factory=list)  # list of dicts with type, stage, position
    clean_text: str = ""
    redacted_length: int = 0


def _luhn_check(number: str) -> bool:
    """Validate a card number using the Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if not digits:
        return False
    digits.reverse()
    total = 0
    for i, d in enumerate(digits):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


class Sanitizer:
    """
    Sanitizes text through four progressive stages:
    1. Pattern Matching with Luhn Validation (PAN, SSN, CVV, Auth tokens)
    2. NER-based PII Detection (Email, Phone, IP)
    3. Domain-Specific Rules (custom regex patterns)
    4. Conservative Fallback (long numeric sequences)
    """

    MODES = ("strict", "pci_dss", "hipaa", "moderate")

    # Compiled regex patterns for Stage 1
    _RE_VISA_MC = re.compile(r'\b([45]\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4})\b')
    _RE_AMEX = re.compile(r'\b(3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5})\b')
    _RE_SSN = re.compile(r'\b(\d{3}-\d{2}-\d{4}|\d{9})\b')
    _RE_CVV = re.compile(r'\b(C[VU][CV][\s:]*\d{3,4})\b', re.IGNORECASE)
    _RE_AUTH = re.compile(
        r'(Bearer\s+[A-Za-z0-9\-._~+/]+=*'
        r'|sk-[A-Za-z0-9]{20,}'
        r'|xox[baprs]-[A-Za-z0-9\-]+'
        r'|eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)'
    )
    _RE_ROUTING = re.compile(r'\b(\d{9})\b')

    # Stage 2 patterns
    _RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
    _RE_PHONE = re.compile(r'(?<!\d)(\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}(?!\d)')
    _RE_IP_EXTERNAL = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b')

    # Stage 4 fallback
    _RE_LONG_NUMERIC = re.compile(r'\b\d{10,}\b')

    def __init__(self, mode: str = "strict", domain_rules: Optional[Dict[str, str]] = None):
        if mode not in self.MODES:
            raise ValueError(f"mode must be one of {self.MODES}, got {mode!r}")
        self.mode = mode
        self.domain_rules: Dict[str, re.Pattern] = {}
        if domain_rules:
            for name, pattern in domain_rules.items():
                self.domain_rules[name] = re.compile(pattern)

    def _is_internal_ip(self, octets) -> bool:
        a, b, c, d = (int(x) for x in octets)
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
        return False

    def _validate_ssn(self, ssn_digits: str) -> bool:
        """Validate SSN area/group/serial rules."""
        digits = ssn_digits.replace("-", "")
        if len(digits) != 9:
            return False
        area = int(digits[:3])
        group = int(digits[3:5])
        serial = int(digits[5:])
        if area in (0, 666) or area >= 900:
            return False
        if group == 0:
            return False
        if serial == 0:
            return False
        return True

    def sanitize(self, text: str) -> RedactionResult:
        """Run text through the four-stage sanitization pipeline."""
        original_length = len(text)
        redactions = []

        # --- Stage 1: Pattern Matching with Luhn Validation ---
        # 16-digit PAN (Visa, Mastercard)
        def redact_pan_16(m):
            raw = m.group(1)
            digits_only = re.sub(r'[\s-]', '', raw)
            if _luhn_check(digits_only):
                redactions.append({"type": "PAN", "stage": 1, "position": m.start()})
                return "[REDACTED:PAN]"
            return raw

        text = self._RE_VISA_MC.sub(redact_pan_16, text)

        # 15-digit PAN (AMEX)
        def redact_pan_15(m):
            raw = m.group(1)
            digits_only = re.sub(r'[\s-]', '', raw)
            if _luhn_check(digits_only):
                redactions.append({"type": "PAN", "stage": 1, "position": m.start()})
                return "[REDACTED:PAN]"
            return raw

        text = self._RE_AMEX.sub(redact_pan_15, text)

        # CVV/CVC
        def redact_cvv(m):
            redactions.append({"type": "CVV", "stage": 1, "position": m.start()})
            return "[REDACTED:CVV]"

        text = self._RE_CVV.sub(redact_cvv, text)

        # Auth tokens
        def redact_auth(m):
            redactions.append({"type": "AUTH_TOKEN", "stage": 1, "position": m.start()})
            return "[REDACTED:AUTH_TOKEN]"

        text = self._RE_AUTH.sub(redact_auth, text)

        # SSN
        def redact_ssn(m):
            raw = m.group(1)
            if self._validate_ssn(raw):
                redactions.append({"type": "SSN", "stage": 1, "position": m.start()})
                return "[REDACTED:SSN]"
            return raw

        text = self._RE_SSN.sub(redact_ssn, text)

        # --- Stage 2: NER-based PII Detection ---
        # Email
        def redact_email(m):
            redactions.append({"type": "EMAIL", "stage": 2, "position": m.start()})
            return "[REDACTED:EMAIL]"

        text = self._RE_EMAIL.sub(redact_email, text)

        # Phone
        def redact_phone(m):
            redactions.append({"type": "PHONE", "stage": 2, "position": m.start()})
            return "[REDACTED:PHONE]"

        text = self._RE_PHONE.sub(redact_phone, text)

        # IP addresses (external only in non-strict; strict redacts external IPs)
        if self.mode == "strict":
            def redact_ip(m):
                octets = (m.group(1), m.group(2), m.group(3), m.group(4))
                if not self._is_internal_ip(octets):
                    redactions.append({"type": "IP", "stage": 2, "position": m.start()})
                    return "[REDACTED:IP]"
                return m.group(0)

            text = self._RE_IP_EXTERNAL.sub(redact_ip, text)

        # --- Stage 3: Domain-Specific Rules ---
        for rule_name, pattern in self.domain_rules.items():
            placeholder = f"[REDACTED:{rule_name.upper()}]"

            def make_redactor(rname, ph):
                def redact_domain(m):
                    redactions.append({"type": rname.upper(), "stage": 3, "position": m.start()})
                    return ph
                return redact_domain

            text = pattern.sub(make_redactor(rule_name, placeholder), text)

        # --- Stage 4: Conservative Fallback ---
        # Any numeric sequence of 10+ digits not already caught
        def redact_long_numeric(m):
            redactions.append({"type": "NUMERIC_ID", "stage": 4, "position": m.start()})
            return "[REDACTED:NUMERIC_ID]"

        text = self._RE_LONG_NUMERIC.sub(redact_long_numeric, text)

        return RedactionResult(
            original_length=original_length,
            redactions=redactions,
            clean_text=text,
            redacted_length=len(text),
        )
