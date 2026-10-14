import re
import base64
import unicodedata

# ---------------------------------------------------------------------------
# Input normalizer & deobfuscation engine
# ---------------------------------------------------------------------------
# Strips invisible Unicode smuggling characters, normalizes homoglyphs via
# NFKC, and surfaces hidden Base64 payloads inline for downstream inspection.
# ---------------------------------------------------------------------------

# Zero-width and Unicode tag characters used for steganography
_ZERO_WIDTH_CHARS = set("\u200b\u200c\u200d\ufeff")
_TAG_RANGE = range(0xE0000, 0xE0080)  # U+E0000 – U+E007F

# Base64 token pattern: standalone alphanumeric+/+= tokens of length >= 24
_BASE64_TOKEN_RE = re.compile(r"(?<!\S)([A-Za-z0-9+/]{24,}={0,2})(?!\S)")

# Keywords that indicate a suspicious decoded Base64 payload
_SUSPICIOUS_KEYWORDS = {"ignore", "admin", "system", "webhook", "http", "select", "password"}


def _strip_zero_width(text: str) -> tuple[str, bool]:
    """Remove zero-width and Unicode tag characters. Returns (cleaned, detected)."""
    chars = []
    detected = False
    for ch in text:
        cp = ord(ch)
        if ch in _ZERO_WIDTH_CHARS or cp in _TAG_RANGE:
            detected = True
        else:
            chars.append(ch)
    return "".join(chars), detected


def _decode_base64_payloads(text: str) -> tuple[str, bool]:
    """Find standalone Base64 tokens that decode to suspicious UTF-8 content."""
    detected = False

    def _replace(match: re.Match) -> str:
        nonlocal detected
        token = match.group(1)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except Exception:
            return token  # not valid Base64/UTF-8, leave unchanged

        lower = decoded.lower()
        if any(kw in lower for kw in _SUSPICIOUS_KEYWORDS):
            detected = True
            return f"{token} [DECODED_BASE64: {decoded}]"
        return token  # benign payload, leave unchanged

    result = _BASE64_TOKEN_RE.sub(_replace, text)
    return result, detected


def normalize_and_deobfuscate(text: str | None) -> dict:
    """
    Multi-layer input normalization and deobfuscation.

    Returns:
        {
            "cleaned_text": str,
            "evasion_detected": bool,
            "techniques": list[str]
        }
    """
    if text is None:
        return {"cleaned_text": "", "evasion_detected": False, "techniques": []}

    techniques: list[str] = []

    # --- Layer 1: Strip zero-width / Unicode tag steganography ------------
    stripped, zw_found = _strip_zero_width(text)
    if zw_found:
        techniques.append("ZERO_WIDTH_STEGANOGRAPHY")

    # --- Layer 2: NFKC normalization (homoglyphs / full-width chars) ------
    normalized = unicodedata.normalize("NFKC", stripped)
    if normalized != stripped:
        techniques.append("UNICODE_HOMOGLYPH_NORMALIZATION")

    # --- Layer 3: Base64 payload deobfuscation ----------------------------
    final, b64_found = _decode_base64_payloads(normalized)
    if b64_found:
        techniques.append("BASE64_PAYLOAD_DEOBFUSCATION")

    return {
        "cleaned_text": final,
        "evasion_detected": len(techniques) > 0,
        "techniques": techniques,
    }
