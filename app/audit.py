import json
import uuid
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

AUDIT_FILE = Path(__file__).resolve().parent.parent / "security_audit.jsonl"
RECENT_EVENTS = deque(maxlen=100)

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
    "NONE": "NONE"
}

# SHA-256 tamper-evident hash chain state
_LAST_HASH = "0" * 64

def log_security_event(
    user_id: str,
    role: str,
    is_tainted: bool,
    tool_name: str | None,
    allowed: bool,
    rule_triggered: str,
    secrets_redacted: int,
    reason: str
) -> dict:
    """
    Records a structured SIEM security event with OWASP classification to disk and memory.
    Each event is chained via SHA-256 for tamper-evident audit integrity.
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
        "prev_hash": _LAST_HASH
    }

    # Compute SHA-256 hash of the event (before entry_hash is added)
    entry_hash = hashlib.sha256(
        json.dumps(event, sort_keys=True).encode("utf-8")
    ).hexdigest()
    event["entry_hash"] = entry_hash
    _LAST_HASH = entry_hash

    RECENT_EVENTS.appendleft(event)

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    return event

def verify_audit_chain() -> dict:
    """
    Verifies the SHA-256 tamper-evident hash chain across all recent events.
    Iterates in chronological order (oldest first), recomputes each hash,
    and verifies both prev_hash linkage and entry_hash integrity.
    """
    events = list(reversed(list(RECENT_EVENTS)))  # chronological order
    if not events:
        return {"chain_valid": True, "checked_events": 0, "head_hash": _LAST_HASH}

    for i, event in enumerate(events):
        # Reconstruct event without entry_hash for verification
        verify_event = {k: v for k, v in event.items() if k != "entry_hash"}
        recomputed = hashlib.sha256(
            json.dumps(verify_event, sort_keys=True).encode("utf-8")
        ).hexdigest()

        # Verify entry_hash integrity
        if recomputed != event.get("entry_hash"):
            return {"chain_valid": False, "checked_events": len(events), "head_hash": _LAST_HASH}

        # Verify prev_hash linkage (first event links to chain start or previous event)
        if i > 0:
            if event["prev_hash"] != events[i - 1]["entry_hash"]:
                return {"chain_valid": False, "checked_events": len(events), "head_hash": _LAST_HASH}

    return {"chain_valid": True, "checked_events": len(events), "head_hash": _LAST_HASH}

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
            "secrets_redacted": redacted
        },
        "chain_integrity": verify_audit_chain(),
        "events": events
    }