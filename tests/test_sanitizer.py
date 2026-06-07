"""
test_sanitizer.py - 25 tests for the four-stage sanitization pipeline.
"""

from compliance_gateway.sanitizer import Sanitizer


class TestStage1Patterns:
    """Pattern Matching with Luhn Validation"""

    def test_valid_visa_pan_redacted(self):
        s = Sanitizer()
        r = s.sanitize("Card number is 4532015112830366")
        assert "[REDACTED:PAN]" in r.clean_text

    def test_valid_mastercard_pan_redacted(self):
        s = Sanitizer()
        r = s.sanitize("MC: 5425233430109903")
        assert "[REDACTED:PAN]" in r.clean_text

    def test_pan_with_spaces_redacted(self):
        s = Sanitizer()
        r = s.sanitize("4532 0151 1283 0366")
        assert "[REDACTED:PAN]" in r.clean_text

    def test_pan_with_dashes_redacted(self):
        s = Sanitizer()
        r = s.sanitize("4532-0151-1283-0366")
        assert "[REDACTED:PAN]" in r.clean_text

    def test_invalid_luhn_not_redacted(self):
        s = Sanitizer()
        r = s.sanitize("1234567890123456")
        assert "[REDACTED:PAN]" not in r.clean_text

    def test_amex_15_digit_redacted(self):
        s = Sanitizer()
        r = s.sanitize("371449635398431")
        assert "[REDACTED:PAN]" in r.clean_text

    def test_ssn_redacted(self):
        s = Sanitizer()
        r = s.sanitize("123-45-6789")
        assert "[REDACTED:SSN]" in r.clean_text

    def test_ssn_without_dashes_redacted(self):
        s = Sanitizer()
        r = s.sanitize("123456789")
        assert "[REDACTED:SSN]" in r.clean_text

    def test_invalid_ssn_area_000_not_redacted(self):
        s = Sanitizer()
        r = s.sanitize("000-12-3456")
        assert "[REDACTED:SSN]" not in r.clean_text

    def test_cvv_redacted(self):
        s = Sanitizer()
        r = s.sanitize("CVV: 123")
        assert "[REDACTED:CVV]" in r.clean_text

    def test_auth_token_redacted(self):
        s = Sanitizer()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        r = s.sanitize(f"Token: {jwt}")
        assert "[REDACTED:AUTH_TOKEN]" in r.clean_text

    def test_openai_key_redacted(self):
        s = Sanitizer()
        r = s.sanitize("sk-abc123abcdefghijklmnopqr")
        assert "[REDACTED:AUTH_TOKEN]" in r.clean_text


class TestStage2NER:
    """NER-based PII Detection"""

    def test_email_redacted(self):
        s = Sanitizer()
        r = s.sanitize("john.doe@company.com")
        assert "[REDACTED:EMAIL]" in r.clean_text

    def test_phone_redacted(self):
        s = Sanitizer()
        r = s.sanitize("555-123-4567")
        assert "[REDACTED:PHONE]" in r.clean_text

    def test_external_ip_redacted_strict(self):
        s = Sanitizer(mode="strict")
        r = s.sanitize("52.14.233.100")
        assert "[REDACTED:IP]" in r.clean_text

    def test_internal_ip_not_redacted(self):
        s = Sanitizer(mode="strict")
        r = s.sanitize("10.0.1.55")
        assert "[REDACTED:IP]" not in r.clean_text


class TestStage3Domain:
    """Domain-Specific Rules"""

    def test_custom_account_pattern(self):
        s = Sanitizer(domain_rules={"ACCOUNT_NUM": r'\b(ACCT-\d{8})\b'})
        r = s.sanitize("ACCT-12345678")
        assert "[REDACTED:ACCOUNT_NUM]" in r.clean_text

    def test_custom_session_token(self):
        s = Sanitizer(domain_rules={"SESSION": r'\b(SES-[A-F0-9]{16})\b'})
        r = s.sanitize("SES-AB12CD34EF560A78")
        assert "[REDACTED:SESSION]" in r.clean_text

    def test_no_domain_rules_no_redaction(self):
        s = Sanitizer()  # no domain rules
        r = s.sanitize("ACCT-12345678")
        assert "[REDACTED:ACCOUNT_NUM]" not in r.clean_text
        assert "ACCT-12345678" in r.clean_text


class TestStage4Fallback:
    """Conservative Fallback for long numeric sequences"""

    def test_long_numeric_redacted(self):
        s = Sanitizer()
        r = s.sanitize("98765432101234")
        assert "[REDACTED:NUMERIC_ID]" in r.clean_text

    def test_short_numeric_not_redacted(self):
        s = Sanitizer()
        r = s.sanitize("500")
        assert "500" in r.clean_text
        assert "[REDACTED" not in r.clean_text


class TestEndToEnd:
    """End-to-end tests"""

    def test_mixed_pii_all_redacted(self):
        s = Sanitizer()
        text = (
            "Card: 4532015112830366 SSN: 123-45-6789 "
            "Email: test@example.com ID: 12345678901234"
        )
        r = s.sanitize(text)
        assert len(r.redactions) >= 4
        assert "4532015112830366" not in r.clean_text
        assert "123-45-6789" not in r.clean_text
        assert "test@example.com" not in r.clean_text

    def test_clean_text_passes_through(self):
        s = Sanitizer()
        text = "The payment-api service returned HTTP 500 at 14:32 UTC"
        r = s.sanitize(text)
        assert r.clean_text == text
        assert len(r.redactions) == 0

    def test_redaction_preserves_context(self):
        s = Sanitizer()
        text = "Please charge card 4532015112830366 for the order."
        r = s.sanitize(text)
        assert "Please charge card" in r.clean_text
        assert "for the order." in r.clean_text
        assert "[REDACTED:PAN]" in r.clean_text

    def test_sanitization_completeness_zero_leakage(self):
        s = Sanitizer()
        known_pans = [
            "4532015112830366",
            "5425233430109903",
            "371449635398431",
            "4532 0151 1283 0366",
            "4532-0151-1283-0366",
        ]
        for pan in known_pans:
            r = s.sanitize(pan)
            digits = pan.replace(" ", "").replace("-", "")
            assert digits not in r.clean_text, f"Leakage detected for PAN: {pan}"
