import json
from pathlib import Path
from app.context import SessionContext
from app.taint import TaintState

POLICY_PATH = Path(__file__).resolve().parent.parent / "policies.json"

def load_policies() -> dict:
    with open(POLICY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def verify_tool_call(llm_output: dict, session: SessionContext, taint: TaintState) -> dict:
    """
    Deterministic authorization, BOLA, and Taint-Tracking check on LLM-proposed tool calls.
    """
    if llm_output.get("type") != "tool_call":
        return {
            "allowed": True,
            "reason": "Plain text response (no tool call requested).",
            "rule_triggered": "NONE"
        }

    tool_name = llm_output.get("tool_name")
    args = llm_output.get("arguments", {})
    policies = load_policies().get("tools", {})

    # 1. Default-Deny: Check if tool exists in policies.json
    if tool_name not in policies:
        return {
            "allowed": False,
            "reason": f"Tool '{tool_name}' is not in the allowlist.",
            "rule_triggered": "UNREGISTERED_TOOL"
        }

    rule = policies[tool_name]

    # 2. RBAC Check: Verify session role is allowed to call this tool
    if session.role not in rule.get("allowed_roles", []):
        return {
            "allowed": False,
            "reason": f"Role '{session.role}' is not authorized to call '{tool_name}'.",
            "rule_triggered": "RBAC_VIOLATION"
        }

    # 3. Dynamic Taint Check: Block sink tools if request ingested untrusted external data
    if taint.is_tainted and rule.get("block_when_tainted", False):
        return {
            "allowed": False,
            "reason": (
                f"Taint Violation: Context is TAINTED by '{taint.source}'. "
                f"Execution of sink tool '{tool_name}' is blocked to prevent data exfiltration."
            ),
            "rule_triggered": "TAINTED_SINK_EXFILTRATION_BLOCK"
        }

    # 4. BOLA Check: Verify resource ownership (target_user_id == session.user_id)
    if rule.get("enforce_bola", False):
        owner_arg = rule.get("owner_arg", "target_user_id")
        requested_owner = str(args.get(owner_arg, "")).strip()

        is_admin_override = (session.role == "admin" and rule.get("allow_admin_override", False))

        if not is_admin_override and requested_owner != session.user_id:
            return {
                "allowed": False,
                "reason": (
                    f"BOLA Violation: Session user '{session.user_id}' attempted to access "
                    f"resource owned by '{requested_owner}' via tool '{tool_name}'."
                ),
                "rule_triggered": "BOLA_CROSS_TENANT_ACCESS"
            }

    return {
        "allowed": True,
        "reason": f"Tool '{tool_name}' verified for user '{session.user_id}'.",
        "rule_triggered": "PASS"
    }