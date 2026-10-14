from pydantic import BaseModel, ConfigDict

class TaintState(BaseModel):
    """
    Immutable taint-tracking state attached to the request lifecycle.
    Once a context ingests untrusted external data, it is marked TAINTED
    and restricted from invoking external network or destructive sink tools.
    """
    model_config = ConfigDict(frozen=True)

    is_tainted: bool
    source: str
    untrusted_length: int

def evaluate_taint(untrusted_context: str | None) -> TaintState:
    """
    Marks the execution context as tainted if any external untrusted data is present.
    """
    if untrusted_context and untrusted_context.strip():
        return TaintState(
            is_tainted=True,
            source="external_untrusted_context",
            untrusted_length=len(untrusted_context)
        )
    return TaintState(
        is_tainted=False,
        source="trusted_internal_only",
        untrusted_length=0
    )