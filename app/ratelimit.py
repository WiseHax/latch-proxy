import time
from collections import defaultdict

# ---------------------------------------------------------------------------
# Sliding-window rate limiter & Denial-of-Wallet quota guard
# ---------------------------------------------------------------------------

MAX_REQUESTS = 25          # per user per window
WINDOW_SECONDS = 60        # sliding window size
MAX_PROMPT_CHARS = 4000    # max combined (prompt + untrusted_context) length

# In-memory sliding window: user_id -> list of request timestamps
_request_log: dict[str, list[float]] = defaultdict(list)


def _prune_window(user_id: str, now: float) -> list[float]:
    """Remove timestamps outside the current sliding window."""
    cutoff = now - WINDOW_SECONDS
    _request_log[user_id] = [
        ts for ts in _request_log[user_id] if ts > cutoff
    ]
    return _request_log[user_id]


def check_rate_and_quota(
    user_id: str,
    prompt: str,
    untrusted_context: str | None,
    simulate_dos: bool = False,
) -> dict:
    """
    Returns {"allowed": bool, "rule_triggered": str, "reason": str}.

    Checks:
      1. If simulate_dos is True or the user exceeds MAX_REQUESTS per window
         -> RATE_LIMIT_DOS_BLOCK
      2. If combined input length exceeds MAX_PROMPT_CHARS
         -> DENIAL_OF_WALLET_QUOTA_EXCEEDED
    """

    now = time.monotonic()
    window = _prune_window(user_id, now)

    # --- Rate limit / DoS check -------------------------------------------
    if simulate_dos or len(window) >= MAX_REQUESTS:
        return {
            "allowed": False,
            "rule_triggered": "RATE_LIMIT_DOS_BLOCK",
            "reason": (
                "Simulated denial-of-service burst detected."
                if simulate_dos
                else f"Rate limit exceeded: {len(window)}/{MAX_REQUESTS} "
                     f"requests in the last {WINDOW_SECONDS}s window."
            ),
        }

    # --- Denial-of-Wallet quota check -------------------------------------
    total_chars = len(prompt) + len(untrusted_context or "")
    if total_chars > MAX_PROMPT_CHARS:
        return {
            "allowed": False,
            "rule_triggered": "DENIAL_OF_WALLET_QUOTA_EXCEEDED",
            "reason": (
                f"Combined input length ({total_chars} chars) exceeds "
                f"maximum allowed ({MAX_PROMPT_CHARS} chars)."
            ),
        }

    # --- Allowed – record this request in the window ----------------------
    _request_log[user_id].append(now)

    return {
        "allowed": True,
        "rule_triggered": "NONE",
        "reason": "Request within rate and quota limits.",
    }
