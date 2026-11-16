"""Tamper-evident evidence ledger.

Every scored case is sealed into a hash chain: each block carries the SHA-256
of the case's forensic content plus the hash of the block before it, so editing
any past record breaks every hash that follows. The chain lives beside the case
log rather than inside it, which keeps `case_log.jsonl` append-only and lets
verification compare two independent files against each other:

    tampered case content  -> recordHash mismatch
    tampered ledger block  -> prevHash link mismatch

No network, no external chain, no keys — the integrity proof is reproducible
from the two files on this machine alone.
"""

import hashlib
import json
from datetime import datetime, timezone

from app.config import LEDGER_PATH

GENESIS_HASH = "0" * 64

# Fields that carry the forensic verdict. Anything outside this set (display
# helpers, enrichment added at read time) stays out of the hash so re-rendering
# a case can never invalidate its own seal.
SEALED_FIELDS = (
    "messageId",
    "sender",
    "senderDomain",
    "subject",
    "timestamp",
    "score",
    "safeScore",
    "flagged",
    "category",
    "fingerprint",
    "evidence",
    "features",
    "geo",
    "tier0",
    "tier1",
)


def canonical_payload(case: dict) -> str:
    """Stable JSON of the sealed fields — key order and spacing fixed."""
    subset = {k: case.get(k) for k in SEALED_FIELDS if k in case}
    return json.dumps(subset, sort_keys=True, separators=(",", ":"), default=str)


def record_hash(case: dict) -> str:
    return hashlib.sha256(canonical_payload(case).encode("utf-8")).hexdigest()


def block_hash(index: int, prev_hash: str, rec_hash: str, sealed_at: str) -> str:
    header = f"{index}|{prev_hash}|{rec_hash}|{sealed_at}"
    return hashlib.sha256(header.encode("utf-8")).hexdigest()


def read_chain() -> list[dict]:
    if not LEDGER_PATH.exists():
        return []
    blocks: list[dict] = []
    with open(LEDGER_PATH, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                block = json.loads(line)
            except ValueError:
                continue
            if isinstance(block, dict):
                blocks.append(block)
    return blocks


def _append_block(block: dict) -> None:
    LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(LEDGER_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(block, separators=(",", ":"), default=str) + "\n")


def seal(case: dict) -> dict:
    """Append one block for `case` and return it."""
    chain = read_chain()
    index = len(chain)
    prev_hash = chain[-1]["hash"] if chain else GENESIS_HASH
    rec_hash = record_hash(case)
    sealed_at = datetime.now(timezone.utc).isoformat()
    block = {
        "index": index,
        "messageId": case.get("messageId"),
        "timestamp": case.get("timestamp"),
        "sealedAt": sealed_at,
        "recordHash": rec_hash,
        "prevHash": prev_hash,
        "hash": block_hash(index, prev_hash, rec_hash, sealed_at),
    }
    _append_block(block)
    return block


def backfill(cases: list[dict]) -> int:
    """Seal any cases the chain does not cover yet. Returns blocks added.

    Both files are append-only and written in the same order, so block i seals
    case i and anything past the current chain height is unsealed. Matching on
    message id instead would mis-handle a message that has been scored twice —
    once from the inbox row and again when it was opened — which is a normal
    thing for the log to contain.
    """
    added = 0
    for case in cases[len(read_chain()):]:
        seal(case)
        added += 1
    return added


def verify(cases: list[dict]) -> dict:
    """Recompute the chain against the case log.

    Returns the per-block verdicts plus a summary the UI can render directly.
    """
    chain = read_chain()
    prev_hash = GENESIS_HASH
    results = []
    broken = []

    for position, block in enumerate(chain):
        issues = []
        message_id = block.get("messageId")
        # Positional pairing: block i seals case i. A message scored twice has
        # two records, so looking it up by id would compare a block against
        # the wrong one of them and report a false tamper.
        case = cases[position] if position < len(cases) else None
        if case is not None and case.get("messageId") != message_id:
            issues.append("Sealed case does not line up with the case log")
            case = None

        if block.get("index") != position:
            issues.append("Block index out of sequence")
        if block.get("prevHash") != prev_hash:
            issues.append("Previous-block link does not match")

        expected_block = block_hash(
            block.get("index", position),
            block.get("prevHash", ""),
            block.get("recordHash", ""),
            block.get("sealedAt", ""),
        )
        if block.get("hash") != expected_block:
            issues.append("Block hash does not match its own header")

        if case is None:
            issues.append("Sealed case is missing from the case log")
        elif record_hash(case) != block.get("recordHash"):
            issues.append("Case content changed after it was sealed")

        entry = {
            "index": block.get("index", position),
            "messageId": message_id,
            "timestamp": block.get("timestamp"),
            "sealedAt": block.get("sealedAt"),
            "recordHash": block.get("recordHash"),
            "prevHash": block.get("prevHash"),
            "hash": block.get("hash"),
            "valid": not issues,
            "issues": issues,
        }
        results.append(entry)
        if issues:
            broken.append(entry)
        prev_hash = block.get("hash", prev_hash)

    unsealed = [c.get("messageId") for c in cases[len(chain):]]

    return {
        "intact": not broken and not unsealed,
        "blocks": results,
        "height": len(chain),
        "broken": broken,
        "unsealed": unsealed,
        "headHash": chain[-1]["hash"] if chain else GENESIS_HASH,
        "verifiedAt": datetime.now(timezone.utc).isoformat(),
        "algorithm": "SHA-256 linked hash chain",
    }


def block_for(message_id: str) -> dict | None:
    """The most recent block sealing this message.

    A message scored from the inbox row and again when opened has two blocks;
    the report shows the latest, which is the one the report's own contents
    came from.
    """
    for block in reversed(read_chain()):
        if block.get("messageId") == message_id:
            return block
    return None
