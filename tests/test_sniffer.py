#!/usr/bin/env python3
"""Unit tests for sniffer redaction functions."""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sniffer import redact_ip, redact_sensitive_data

def test_redact_ip():
    """Test IP redaction."""
    result = redact_ip("192.168.1.42")
    assert result == "192.168.1.xxx", f"Expected '192.168.1.xxx', got '{result}'"
    print("✓ test_redact_ip passed")

def test_redact_email():
    """Test email redaction."""
    text = "Contact me at user@example.com for info"
    result = redact_sensitive_data(text)
    assert "[REDACTED_EMAIL]" in result, "Email not redacted"
    assert "user@example.com" not in result, "Email still visible"
    print("✓ test_redact_email passed")

def test_redact_password():
    """Test password redaction."""
    text = "Login with password=mysecret123&username=bob"
    result = redact_sensitive_data(text)
    assert "mysecret123" not in result, "Password still visible"
    assert "[REDACTED]" in result, "Password not redacted"
    print("✓ test_redact_password passed")

def test_redact_token():
    """Test token redaction."""
    text = "token=abc123xyz789&action=login"
    result = redact_sensitive_data(text)
    assert "abc123xyz789" not in result, "Token still visible"
    assert "[REDACTED]" in result, "Token not redacted"
    print("✓ test_redact_token passed")

if __name__ == "__main__":
    test_redact_ip()
    test_redact_email()
    test_redact_password()
    test_redact_token()
    print("\n✅ All tests passed!")
