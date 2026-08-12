"""Audit-log secret redaction (spec §7, §9.6)."""

from __future__ import annotations

from skrecon.audit import AuditLog


def test_redacts_known_secret_value():
    a = AuditLog(path=None, secrets=("SUPERSECRETKEY",))
    out = a.redact("shodan host --key SUPERSECRETKEY 1.2.3.4")
    assert "SUPERSECRETKEY" not in out
    assert "REDACTED" in out


def test_redacts_keyvalue_patterns():
    a = AuditLog(path=None)
    assert "abc123" not in a.redact("GET /x?api_key=abc123")
    assert "tok_xyz" not in a.redact("Authorization: Bearer tok_xyz")
    assert "hunter2" not in a.redact("mysqldump -u root -p hunter2")


def test_record_redacts_before_write(tmp_path):
    path = tmp_path / "audit.jsonl"
    a = AuditLog(path=path, secrets=("KEY123",))
    a.record(module="shodan", action="api-call", outcome="ok",
             command="curl 'https://api?token=KEY123'")
    text = path.read_text(encoding="utf-8")
    assert "KEY123" not in text
    assert "shodan" in text


def test_record_redacts_api_key_in_target_url(tmp_path):
    # Shodan/DeHashed put the key in the request URL, which lands in `target`.
    path = tmp_path / "audit.jsonl"
    a = AuditLog(path=path, secrets=("SHODANKEY",))
    a.record(module="shodan", action="http-get", outcome="ok",
             target="https://api.shodan.io/shodan/host/1.2.3.4?key=SHODANKEY")
    assert "SHODANKEY" not in path.read_text(encoding="utf-8")
