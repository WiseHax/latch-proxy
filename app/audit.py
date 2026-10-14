import json
import uuid
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
    "PASS": "NONE",
    "NONE": "NONE"
}

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
    """
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
        "reason": reason
    }

    RECENT_EVENTS.appendleft(event)

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

    return event

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
        "events": events
    }