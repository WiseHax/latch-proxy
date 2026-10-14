import hashlib
import json
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

AUDIT_FILE = Path(__file__).resolve().parent.parent / "security_audit.jsonl"
RECENT_EVENTS: deque[dict] = deque(maxlen=100)
_LAST_HASH = "0" * 64

OWASP_MAPPING = {
    "HMAC_SIGNATURE_MISMATCH": "OWASP API2:2023 - Broken Authentication (Header Spoofing)",
    "BOLA_CROSS_TENANT_ACCESS": "OWASP API1:2023 - Broken Object Level Authorization",
    "TAINTED_SINK_EXFILTRATION_BLOCK": "OWASP LLM01:2025 - Indirect Prompt Injection / Exfiltration",
    "RBAC_VIOLATION": "OWASP API5:2023 - Broken Function Level Authorization",
    "UNREGISTERED_TOOL": "OWASP LLM07:2025 - Excessive Agency",
    "RATE_LIMIT_DOS_BLOCK": "OWASP API4:2023 - Unrestricted Resource Consumption",
    "DENIAL_OF_WALLET_QUOTA_EXCEEDED": "OWASP LLM10:2025 - Unbounded Consumption (Denial of Wallet)",
    "SSRF_INTERNAL_TARGET_BLOCK": "OWASP API7:2023 - Server Side Request Forgery (SSRF)",
    "MALICIOUS_TOOL_ARGUMENT_PAYLOAD": "OWASP LLM05:2025 - Improper Output Handling (Argument Injection)",
    "CANARY_SYSTEM_PROMPT_LEAK": "OWASP LLM07:2025 - System Prompt Leakage (Canary Triggered)",
    "PASS": "NONE",
    "NONE": "NONE",
}


def _compute_event_hash(event_without_hash: dict) -> str:
    canonical = json.dumps(event_without_hash, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _hydrate_chain_from_disk() -> None:
    """
    Loads existing hash-chained events from security_audit.jsonl on startup
    so _LAST_HASH continuity is preserved across server restarts.
    """
    global _LAST_HASH
    if not AUDIT_FILE.exists():
        return

    try:
        with open(AUDIT_FILE, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        valid_chain_events = []
        expected_prev = "0" * 64

        for line in lines:
            record = json.loads(line)
            if "entry_hash" not in record or "prev_hash" not in record:
                # Legacy pre-v3.0 log entry without hash fields; reset chain cleanly
                valid_chain_events.clear()
                expected_prev = "0" * 64
                continue

            check_copy = {k: v for k, v in record.items() if k != "entry_hash"}
            if record["prev_hash"] == expected_prev and _compute_event_hash(check_copy) == record["entry_hash"]:
                valid_chain_events.append(record)
                expected_prev = record["entry_hash"]
            else:
                valid_chain_events.clear()
                expected_prev = "0" * 64

        for ev in valid_chain_events[-100:]:
            RECENT_EVENTS.appendleft(ev)

        if valid_chain_events:
            _LAST_HASH = valid_chain_events[-1]["entry_hash"]
    except Exception:
        _LAST_HASH = "0" * 64


# Hydrate chain state when module loads
_hydrate_chain_from_disk()


def log_security_event(
    user_id: str,
    role: str,
    is_tainted: bool,
    tool_name: str | None,
    allowed: bool,
    rule_triggered: str,
    secrets_redacted: int,
    reason: str,
) -> dict:
    """
    Records a structured SIEM security event with OWASP classification and SHA-256 hash chain.
    """
    global _LAST_HASH

    owasp_tag = OWASP_MAPPING.get(rule_triggered, "NONE")
    if secrets_redacted > 0 and owasp_tag == "NONE":
        owasp_tag = "OWASP LLM02:2025 - Sensitive Information Disclosure"

    event = {
        "event_id": str(uuid.uuid4())[:8],
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "user_id": user_id,
        "role": role,
        "is_tainted": is_tainted,
        "tool_name": tool_name or "text_response",
        "verdict": "ALLOWED" if allowed else "BLOCKED",
        "rule_triggered": rule_triggered,
        "owasp_category": owasp_tag,
        "secrets_redacted": secrets_redacted,
        "reason": reason,
        "prev_hash": _LAST_HASH,
    }

    entry_hash = _compute_event_hash(event)
    event["entry_hash"] = entry_hash
    _LAST_HASH = entry_hash

    RECENT_EVENTS.appendleft(event)

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    return event


def verify_audit_chain() -> dict:
    """
    Verifies cryptographic linkage (prev_hash -> entry_hash) across in-memory SIEM events.
    """
    chronological = list(reversed(RECENT_EVENTS))
    if not chronological:
        return {"chain_valid": True, "checked_events": 0, "head_hash": _LAST_HASH}

    expected_prev = chronological[0].get("prev_hash", "0" * 64)

    for idx, ev in enumerate(chronological):
        stored_hash = ev.get("entry_hash", "")
        prev_hash = ev.get("prev_hash", "")

        if prev_hash != expected_prev:
            return {
                "chain_valid": False,
                "checked_events": idx,
                "broken_at_event": ev.get("event_id"),
                "reason": "prev_hash mismatch in ledger chain",
                "head_hash": _LAST_HASH,
            }

        check_copy = {k: v for k, v in ev.items() if k != "entry_hash"}
        recomputed = _compute_event_hash(check_copy)
        if recomputed != stored_hash:
            return {
                "chain_valid": False,
                "checked_events": idx,
                "broken_at_event": ev.get("event_id"),
                "reason": "SHA-256 entry_hash integrity check failed",
                "head_hash": _LAST_HASH,
            }

        expected_prev = stored_hash

    return {
        "chain_valid": True,
        "checked_events": len(chronological),
        "head_hash": _LAST_HASH,
    }


def get_audit_summary() -> dict:
    events = list(RECENT_EVENTS)
    total = len(events)
    blocked = sum(1 for e in events if e["verdict"] == "BLOCKED")
    tainted = sum(1 for e in events if e["is_tainted"])
    redacted = sum(e["secrets_redacted"] for e in events)

    return {
        "metrics": {
            "total_requests": total,
            "blocked_attacks": blocked,
            "tainted_contexts": tainted,
            "secrets_redacted": redacted,
        },
        "chain_integrity": verify_audit_chain(),
        "events": events,
    }