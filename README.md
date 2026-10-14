# latch-proxy

A zero-trust FastAPI reverse proxy and runtime security gateway that protects LLM-integrated applications from **Indirect Prompt Injection (OWASP LLM01)**, **Broken Object Level Authorization / BOLA (OWASP API1)**, **Header Spoofing (OWASP API2)**, **Data Exfiltration**, and **Sensitive Information Disclosure (OWASP LLM02)**.

---

## Defense-in-Depth Architecture

1. **HMAC-SHA256 Identity & Session Lock (`app/context.py`, `app/crypto.py`):** Verifies cryptographic session signatures (`X-Latch-Signature`) using constant-time comparison (`hmac.compare_digest`) and binds `user_id` and `role` into an immutable Pydantic state object (`frozen=True`).
2. **Cryptographic Context Spotlighting (`app/delimiter.py`):** Isolates untrusted external inputs (RAG chunks, emails, web scrapes) inside randomized per-request hex boundaries (`[[UNTRUSTED_DATA_START_<hex>]]`) and sanitizes spoofed closing tags.
3. **Dynamic Taint-Tracking Engine (`app/taint.py`):** Automatically marks the request execution context as `TAINTED` when untrusted external data is ingested, preventing downstream exfiltration sinks (`send_external_webhook`, `delete_user_account`) from executing.
4. **Deterministic BOLA & RBAC Policy Guard (`app/guard.py`):** Intercepts model-proposed tool calls and validates resource ownership (`target_user_id == session.user_id`) and role permissions against `policies.json`.
5. **Egress DLP Secret Scrubber & SIEM Telemetry (`app/scrubber.py`, `app/audit.py`, `app/dashboard.py`):** Redacts leaked API keys, JWTs, and credentials on egress while streaming structured OWASP-mapped events to `security_audit.jsonl` and a split-pane SecOps web console (`/dashboard`).

---

## Project Structure

```text
latch-proxy/
├── app/
│   ├── main.py          # FastAPI reverse proxy & routes (/v1/chat, /v1/audit, /dashboard)
│   ├── context.py       # Immutable session binding & header verification
│   ├── crypto.py        # Constant-time HMAC-SHA256 signature verification
│   ├── delimiter.py     # Per-request cryptographic boundary tagging
│   ├── taint.py         # Dynamic taint-tracking state engine
│   ├── guard.py         # Deterministic RBAC, BOLA & taint sink enforcement
│   ├── scrubber.py      # Outbound regex DLP secret scrubber
│   ├── audit.py         # Structured JSONL SIEM logger with OWASP Top 10 mapping
│   └── dashboard.py     # Split-pane SecOps packet inspector UI
├── policies.json        # Declarative tool permissions, BOLA & taint sink rules
├── test_attacks.py      # 8-stage automated security regression suite
├── requirements.txt     # Dependencies
└── README.md
```

---

## Quickstart

```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

* **SecOps Packet Inspector Console:** `http://127.0.0.1:8000/dashboard`
* **Interactive OpenAPI Docs:** `http://127.0.0.1:8000/docs`

---

## Automated Security Regression Suite

Run the 8-scenario attack suite against the local proxy:

```bash
.\venv\Scripts\python.exe test_attacks.py
```

```text
=== Running latch-proxy Security Suite v2.0 ===

[TEST 1] Authorized Self-Access (user_42 -> user_42): HTTP 200 | Expected: 200
[TEST 2] BOLA Cross-Tenant Hijack (user_42 -> admin_01): HTTP 403 | Rule: BOLA_CROSS_TENANT_ACCESS | Expected: 403
[TEST 3] Authorized Admin Override (role=admin):       HTTP 200 | Expected: 200
[TEST 4] Egress Secret Scrubber:                       HTTP 200 | Redacted: 2 secrets
[TEST 5] Tainted Sink Exfiltration (Webhook Blocked):  HTTP 403 | Rule: TAINTED_SINK_EXFILTRATION_BLOCK | Expected: 403
[TEST 6] Untainted Webhook Call (No external data):    HTTP 200 | Expected: 200
[TEST 7] Valid HMAC-SHA256 Signed Session:             HTTP 200 | Expected: 200
[TEST 8] HMAC Role-Spoofing Attack (user -> admin):    HTTP 401 | Expected: 401
```