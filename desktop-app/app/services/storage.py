import json
import os
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from app.config import CASE_LOG_PATH, FINGERPRINT_INDEX_PATH


def atomic_write_json(path: Path, data: dict) -> None:
    tmp_fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp_path, str(path))
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def json_safe(value):
    """Replace NaN/Infinity with None so the value is valid JSON.

    Forensic features use NaN for "could not be determined". JSON has no such
    literal — `json.dumps` emits a bare `NaN`, which is not valid JSON and which
    FastAPI refuses outright — so unknowns travel as null and are read back as
    NaN by the model.
    """
    import math

    if isinstance(value, float):
        return None if (math.isnan(value) or math.isinf(value)) else value
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    return value


_logged_ids: set | None = None


def has_case(message_id: str) -> bool:
    """Whether this message is already in the case log.

    Gmail re-renders the inbox constantly, so the same row is scored many times
    over a session. The log is append-only and hash-chained, so it records each
    message once rather than once per re-render.
    """
    global _logged_ids
    if _logged_ids is None:
        _logged_ids = {c.get("messageId") for c in _read_case_log()}
    return message_id in _logged_ids


def content_key(sender: str, subject: str) -> str:
    """Identify a message by what both Gmail views can see.

    The inbox row and the opened message carry different ids (a hash of the
    row text vs Gmail's own message id), so the id cannot link them. Sender
    and subject can, once whitespace and case are normalised.
    """
    return f"{(sender or '').strip().lower()}|{' '.join((subject or '').split()).lower()}"


_full_analyses: dict | None = None


def full_analysis_for(sender: str, subject: str) -> dict | None:
    """The latest /api/analyze verdict for this sender and subject, if any.

    An inbox badge is scored from the subject and preview line alone; once the
    message has been opened and read in full, that verdict supersedes it.
    """
    global _full_analyses
    if _full_analyses is None:
        _full_analyses = {}
        for c in _read_case_log():
            if c.get("source") != "inbox-scan" and c.get("sender") and c.get("subject"):
                _full_analyses[content_key(c.get("sender"), c.get("subject"))] = c
    if not sender or not subject:
        return None
    return _full_analyses.get(content_key(sender, subject))


def append_case(record: dict) -> None:
    global _logged_ids
    record.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
    with open(CASE_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")
    if _logged_ids is not None:
        _logged_ids.add(record.get("messageId"))
    if (_full_analyses is not None and record.get("source") != "inbox-scan"
            and record.get("sender") and record.get("subject")):
        _full_analyses[content_key(record.get("sender"), record.get("subject"))] = record
    from app.services import ledger
    ledger.seal(record)


def _iter_records(text: str):
    """Yield every JSON object in a case-log line.

    A seed-data bug wrote records joined by a literal backslash-n instead of a
    newline, which put many records on one physical line. Decoding
    incrementally recovers those rather than discarding the whole line.
    """
    decoder = json.JSONDecoder()
    pos, length = 0, len(text)
    while pos < length:
        while pos < length and text[pos] in ' \t\r\n':
            pos += 1
        if pos < length and text.startswith("\\n", pos):
            pos += 2
            continue
        if pos >= length:
            return
        try:
            record, pos = decoder.raw_decode(text, pos)
        except ValueError:
            return
        if isinstance(record, dict):
            yield record


def _read_case_log() -> list[dict]:
    if not CASE_LOG_PATH.exists():
        return []
    cases: list[dict] = []
    with open(CASE_LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            cases.extend(_iter_records(line))
    return cases


def read_cases_today() -> list[dict]:
    today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    cases: list[dict] = []
    for rec in _read_case_log():
        ts = rec.get("timestamp")
        if not ts:
            continue
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if dt >= today:
            cases.append(rec)
    return cases


def read_all_cases() -> list[dict]:
    return _read_case_log()


def read_fingerprints() -> dict:
    if not FINGERPRINT_INDEX_PATH.exists():
        return {}
    with open(FINGERPRINT_INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def write_fingerprints(data: dict) -> None:
    atomic_write_json(FINGERPRINT_INDEX_PATH, data)
