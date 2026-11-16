import hashlib
import re


def compute_fingerprint(email_text: str) -> str:
    text = email_text
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<EMAIL>", text)
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "<DATE>", text)
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>", text)
    text = re.sub(r"\b\+?\d[\d\s\-()]{7,}\b", "<PHONE>", text)
    text = re.sub(r"\b\d{1,3}(,\d{3})*(\.\d+)?\b", "<AMT>", text)
    text = re.sub(r"\b[A-Z][a-z]+ [A-Z][a-z]+\b", "<NAME>", text)
    normalized = text.strip().lower()
    h = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return h


def compare_fingerprints(fp1: str, fp2: str) -> float:
    if fp1 == fp2:
        return 1.0
    return 0.0
