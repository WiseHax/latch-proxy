import re
import ipaddress
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Post-guard tool argument inspector
# ---------------------------------------------------------------------------
# Inspects string values in LLM-proposed tool call arguments for SSRF
# targeting internal/cloud-metadata endpoints and path traversal / command
# injection payloads.
# ---------------------------------------------------------------------------

# URL pattern to extract from argument values
_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)

# Hostnames that are always blocked (case-insensitive comparison)
_BLOCKED_HOSTS = {"localhost", "0.0.0.0", "169.254.169.254"}

# Shell injection / path traversal patterns
_INJECTION_PATTERNS = [
    "../",
    "..\\",
    "/etc/passwd",
    "; rm ",
    "| bash",
    "$(",
    "`",
]


def _is_internal_host(hostname: str) -> bool:
    """Check if a hostname resolves to a blocked, loopback, private, link-local, or reserved address."""
    if hostname.lower() in _BLOCKED_HOSTS:
        return True
    # Strip IPv6 brackets
    bare = hostname.strip("[]")
    try:
        addr = ipaddress.ip_address(bare)
        return (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_reserved
        )
    except ValueError:
        return False


def inspect_tool_arguments(llm_output: dict) -> dict:
    """
    Inspect all string values in tool call arguments for SSRF and injection payloads.

    Returns:
        {"allowed": bool, "rule_triggered": str, "reason": str}
    """
    if llm_output.get("type") != "tool_call":
        return {"allowed": True, "rule_triggered": "NONE", "reason": "Not a tool call."}

    arguments = llm_output.get("arguments", {})

    for key, value in arguments.items():
        if not isinstance(value, str):
            continue

        # --- SSRF Protection ----------------------------------------------
        for url_match in _URL_RE.findall(value):
            try:
                parsed = urlparse(url_match)
                hostname = parsed.hostname or ""
            except Exception:
                continue

            if _is_internal_host(hostname):
                return {
                    "allowed": False,
                    "rule_triggered": "SSRF_INTERNAL_TARGET_BLOCK",
                    "reason": (
                        f"Tool argument '{key}' contains URL targeting internal/cloud-metadata "
                        f"host '{hostname}': {url_match}"
                    ),
                }

        # --- Path Traversal & Command Injection Protection ----------------
        for pattern in _INJECTION_PATTERNS:
            if pattern in value:
                return {
                    "allowed": False,
                    "rule_triggered": "MALICIOUS_TOOL_ARGUMENT_PAYLOAD",
                    "reason": (
                        f"Tool argument '{key}' contains suspicious payload pattern: "
                        f"'{pattern}'"
                    ),
                }

    return {"allowed": True, "rule_triggered": "NONE", "reason": "Tool arguments are clean."}
