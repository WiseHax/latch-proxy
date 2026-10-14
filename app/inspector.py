import ipaddress
import re
from urllib.parse import urlparse, unquote

# Blocked internal hostnames, cloud metadata aliases, and DNS rebinding suffixes
BLOCKED_HOSTS = {
    "localhost",
    "0.0.0.0",
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "100.100.100.200",  # Alibaba Cloud IMDS
}

DNS_REBINDING_SUFFIXES = (
    ".nip.io",
    ".sslip.io",
    ".xip.io",
    ".localtest.me",
    ".lvh.me",
    ".vcap.me",
    ".local",
    ".internal",
    ".localhost",
)

URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)

DANGEROUS_PATTERNS = [
    "../",
    "..\\",
    "/etc/passwd",
    "/etc/shadow",
    "c:\\windows\\system32",
    "; rm ",
    "| bash",
    "| sh",
    "$(",
    "`",
]


def _is_forbidden_host(hostname: str) -> tuple[bool, str]:
    host = hostname.strip().lower().rstrip(".")

    if not host:
        return True, "Empty hostname in URL"

    if host in BLOCKED_HOSTS:
        return True, f"Blocked internal/metadata host '{host}'"

    # Block wildcard DNS rebinding domains (e.g., 169.254.169.254.nip.io)
    if host.endswith(DNS_REBINDING_SUFFIXES):
        return True, f"Wildcard DNS rebinding domain '{host}' is forbidden"

    # Block embedded private/metadata IPv4 patterns inside subdomains
    if re.search(r"(^|\.)(127\.0\.0\.1|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)(\.|$)", host):
        return True, f"Embedded internal IP address detected in hostname '{host}'"

    # Check literal IP addresses (IPv4 / IPv6)
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        if (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return True, f"Non-public IP address '{ip}' is forbidden"
    except ValueError:
        pass

    return False, ""


def inspect_tool_arguments(llm_output: dict) -> dict:
    """
    Deep inspection of tool-call arguments for SSRF (including DNS rebinding)
    and URL-encoded path traversal / command injection payloads.
    """
    if llm_output.get("type") != "tool_call":
        return {
            "allowed": True,
            "rule_triggered": "NONE",
            "reason": "No tool call arguments to inspect.",
        }

    args = llm_output.get("arguments", {})
    if not isinstance(args, dict):
        return {"allowed": True, "rule_triggered": "NONE", "reason": "Empty arguments."}

    for key, raw_value in args.items():
        if not isinstance(raw_value, str):
            continue

        # Decode URL-encoded sequences twice to catch single/double-encoded traversal (%2e%2e%2f)
        decoded_value = unquote(unquote(raw_value))
        lower_val = decoded_value.lower()

        # 1. Check URLs for SSRF & DNS Rebinding
        for match in URL_REGEX.findall(decoded_value):
            parsed = urlparse(match)
            hostname = parsed.hostname or ""
            is_bad, detail = _is_forbidden_host(hostname)
            if is_bad:
                return {
                    "allowed": False,
                    "rule_triggered": "SSRF_INTERNAL_TARGET_BLOCK",
                    "reason": f"SSRF Firewall blocked argument '{key}': {detail}.",
                }

        # 2. Check for Path Traversal & Command Injection
        for pattern in DANGEROUS_PATTERNS:
            if pattern in lower_val:
                return {
                    "allowed": False,
                    "rule_triggered": "MALICIOUS_TOOL_ARGUMENT_PAYLOAD",
                    "reason": f"Argument '{key}' contains forbidden payload pattern '{pattern}'.",
                }

    return {
        "allowed": True,
        "rule_triggered": "PASS",
        "reason": "All tool arguments passed deep SSRF and payload inspection.",
    }
