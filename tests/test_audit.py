import pytest
import logging

@pytest.mark.asyncio
async def test_landlock_denial_categorized_correctly(tmp_path, caplog):
    from app.runtime.sandbox_manager.wiring import _run_sandboxed
    from app.runtime.sandbox_manager.authorization_receipt import AuthorizationReceipt

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret")
    escape = allowed / "escape"
    escape.symlink_to(outside)  # le seul cas où Landlock diverge réellement

    receipt = AuthorizationReceipt(resource_type="file", action="read", identifier=str(escape))
    with caplog.at_level(logging.WARNING):
        with pytest.raises(PermissionError):
            await _run_sandboxed(receipt, "file_read", identifier=str(escape), worker_kwargs={"path": str(escape)})
    assert any('"landlock_denial"' in r.message for r in caplog.records)


def test_pii_redaction_masks_email_and_phone():
    from app.runtime.output_guardrails.main import redact_pii
    redacted, findings = redact_pii("Contactez-moi à jean@example.com ou au 0612345678.")
    assert "[EMAIL_REDACTED]" in redacted
    assert "[PHONE_REDACTED]" in redacted
    assert len(findings) == 2


def test_credit_card_luhn_rejects_invalid_number():
    from app.runtime.output_guardrails.main import detect_pii
    findings = detect_pii("Le numéro 1234 5678 9012 3456 n'est pas une vraie carte.")
    assert not any(f["type"] == "credit_card" for f in findings)


def test_grounding_score_high_for_relevant_context():
    from app.runtime.output_guardrails.main import grounding_score
    score = grounding_score("Landlock isole les fichiers au niveau noyau.", ["Landlock restreint l'accès filesystem au niveau noyau."])
    assert score > 0.5