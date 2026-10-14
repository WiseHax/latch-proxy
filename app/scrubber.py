import re
import math
from collections import Counter

# Regex patterns for common leaked credentials and tokens
SECRET_PATTERNS = [
    (r"sk-[a-zA-Z0-9_-]{20,}", "[REDACTED_OPENAI_OR_OPENROUTER_KEY]"),
    (r"AIza[0-9A-Za-z_-]{35}", "[REDACTED_GOOGLE_API_KEY]"),
    (r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}", "[REDACTED_JWT_TOKEN]"),
    (r"(?i)(api_key|secret_key|password)\s*[:=]\s*['\"]?[^\s'\"]+['\"]?", "[REDACTED_CREDENTIAL_ASSIGNMENT]")
]

ENTROPY_THRESHOLD = 4.2
MIN_TOKEN_LENGTH = 28


def calculate_shannon_entropy(token: str) -> float:
    """Calculate Shannon entropy (bits per character) for a string."""
    length = len(token)
    if length == 0:
        return 0.0
    counts = Counter(token).values()
    return -sum((c / length) * math.log2(c / length) for c in counts)


def _has_mixed_charset(token: str) -> bool:
    """Check if token contains a mix of uppercase, lowercase, and digits."""
    has_upper = any(c.isupper() for c in token)
    has_lower = any(c.islower() for c in token)
    has_digit = any(c.isdigit() for c in token)
    return has_upper and has_lower and has_digit


def scrub_output(text: str) -> dict:
    """
    Scans outgoing AI responses for leaked secrets and redacts them before returning to the client.
    Uses both regex pattern matching and Shannon entropy analysis.
    """
    scrubbed_text = text
    redactions_made = 0

    for pattern, replacement in SECRET_PATTERNS:
        matches = re.findall(pattern, scrubbed_text)
        if matches:
            redactions_made += len(matches)
            scrubbed_text = re.sub(pattern, replacement, scrubbed_text)

    # --- Shannon entropy scan for unknown high-entropy secrets ------------
    tokens = scrubbed_text.split()
    new_tokens = []
    for token in tokens:
        # Skip already-redacted tags and URLs
        if token.startswith("[REDACTED_") or token.startswith("http"):
            new_tokens.append(token)
            continue
        # Strip trailing punctuation for analysis but keep it for reconstruction
        stripped = token.rstrip(".,;:!?\"')")
        if (
            len(stripped) >= MIN_TOKEN_LENGTH
            and _has_mixed_charset(stripped)
            and calculate_shannon_entropy(stripped) > ENTROPY_THRESHOLD
        ):
            redactions_made += 1
            new_tokens.append("[REDACTED_HIGH_ENTROPY_SECRET]")
        else:
            new_tokens.append(token)
    scrubbed_text = " ".join(new_tokens)

    return {
        "clean_text": scrubbed_text,
        "secrets_redacted": redactions_made
    }