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

def test_third_party_logs_never_reach_audit_file(tmp_path):
    """audit.jsonl ne contient que des lignes JSON structurées : un logger
    tiers (httpx, google-genai...) ne doit jamais y écrire."""
    import json
    from logging.handlers import RotatingFileHandler
    from app.runtime.audit_manager import main as audit_main

    audit_main._configured = False
    audit_logger = logging.getLogger("audit")
    handlers_before = list(audit_logger.handlers)
    try:
        audit_main.configure_audit_logging(log_dir=str(tmp_path))
        logging.getLogger("google_genai.models").info("AFC is enabled with max remote calls: 10.")
        audit_main.get_audit_logger("runtime").warning("rag_document_rejected_integrity", document_id="x")
        for h in audit_logger.handlers:
            h.flush()
        lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
        assert len(lines) == 1
        event = json.loads(lines[0])
        assert event["event"] == "rag_document_rejected_integrity"
        assert event["logger"] == "audit.runtime"
    finally:
        for h in list(audit_logger.handlers):
            if h not in handlers_before:
                audit_logger.removeHandler(h)
                h.close()
        audit_main._configured = True


def test_path_prefix_matches_by_path_components(tmp_path):
    import json
    from app.runtime.policy_engine.main import PolicyEngine
    rules = {"version": "t", "rules": [{
        "id": "r", "resource": "file", "action": "read", "path_prefix": str(tmp_path / "up") + "/",
        "effect": "allow", "conditions": {}}]}
    f = tmp_path / "rules.json"
    f.write_text(json.dumps(rules))
    engine = PolicyEngine(str(f))
    ok = engine.evaluate({"role": "user"}, {"type": "file", "path": str(tmp_path / "up" / "a.txt")}, "read")
    sibling = engine.evaluate({"role": "user"}, {"type": "file", "path": str(tmp_path / "up_evil" / "a.txt")}, "read")
    assert ok.allowed is True
    assert sibling.allowed is False
