import re
import numpy as np
from chromadb.utils import embedding_functions
from app.runtime.output_guardrails.config import load_output_guardrails_config

_config = load_output_guardrails_config()
GROUNDING_THRESHOLD = _config["grounding_threshold"]

_PII_PATTERNS = { #pii personally identifiable informations: concern a certain person name, phone, email...
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "phone": re.compile(r"(?:\+212|0)[5-7]\d{8}\b|(?:\+33|0)[1-9](?:[\s.-]?\d{2}){4}"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

_ef = embedding_functions.DefaultEmbeddingFunction() #transforme un texte en des vecteur


def _luhn_valid(number: str) -> bool: #algorithme de Luhn, utilisé notamment pour vérifier la structure de numéros de cartes bancaires.
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def detect_pii(text: str) -> list[dict]: #si le texte contient un des pii
    findings = []
    for label, pattern in _PII_PATTERNS.items():
        for m in pattern.finditer(text):
            if label == "credit_card" and not _luhn_valid(m.group()):
                continue
            findings.append({"type": label, "span": m.span()})
    return findings


def redact_pii(text: str) -> tuple[str, list[dict]]: #score d'accord avec les doc rag
    findings = detect_pii(text)
    redacted = text
    for f in sorted(findings, key=lambda x: x["span"][0], reverse=True):
        start, end = f["span"]
        redacted = redacted[:start] + f"[{f['type'].upper()}_REDACTED]" + redacted[end:]
    return redacted, findings


def grounding_score(response: str, context_chunks: list[str]) -> float:
    if not context_chunks:
        return 0.0
    embeddings = np.array(_ef([response] + context_chunks))
    response_vec, context_vecs = embeddings[0], embeddings[1:]
    sims = context_vecs @ response_vec / (np.linalg.norm(context_vecs, axis=1) * np.linalg.norm(response_vec) + 1e-8)
    return float(np.max(sims))