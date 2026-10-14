import re

# Regex patterns for common leaked credentials and tokens
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_-]{20,}", "[REDACTED_OPENAI_OR_OPENROUTER_KEY]"),
    (r"AIza[0-9A-Za-z_-]{35}", "[REDACTED_GOOGLE_API_KEY]"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED_JWT_TOKEN]"),
    (r"(?i)(api_key|secret_key|password)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", "[REDACTED_CREDENTIAL_ASSIGNMENT]")
]

def scrub_output(text: str) -> dict:
    """
    Scans outgoing AI responses for leaked secrets and redacts them before returning to the client.
    """
    scrubbed_text = text
    redactions_made = 0

    for pattern, replacement in SECRET_PATTERNS:
        matches = re.findall(pattern, scrubbed_text)
        if matches:
            redactions_made += len(matches)
            scrubbed_text = re.sub(pattern, replacement, scrubbed_text)

    return {
        "clean_text": scrubbed_text,
        "secrets_redacted": redactions_made
    }