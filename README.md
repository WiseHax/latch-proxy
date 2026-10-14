# latch-proxy

A lightweight, zero-trust FastAPI reverse proxy that protects LLM-powered applications from **Indirect Prompt Injection (OWASP LLM01)**, **Broken Object Level Authorization / BOLA (OWASP API1)** on tool calls, and **outbound credential leaks**.

---

## Architecture & Security Layers

1. **Immutable Session Binding (`app/context.py`):** Extracts the authenticated caller's `user_id` and `role` from HTTP headers and locks them into a frozen server-side Pydantic state object (`frozen=True`) that prompt payloads cannot overwrite.
2. **Cryptographic Context Spotlighting (`app/delimiter.py`):** Wraps untrusted external data (RAG documents, user bios, database rows) inside per-request randomized hex boundaries (`[[UNTRUSTED_DATA_START_<hex>]]`) and strips spoofed closing tags to prevent tag-escape attacks.
3. **Deterministic BOLA & RBAC Tool Guard (`app/guard.py`):** Intercepts model-generated tool calls before execution and enforces resource ownership (`target_user_id == session.user_id`) and role permissions defined in `policies.json`.
4. **Egress DLP Scrubber (`app/scrubber.py`):** Scans outgoing responses and redacts leaked API keys (`sk-...`, `AIza...`), JWTs, and plaintext credential assignments before returning output to the client.

---

## Project Structure

```text
latch-proxy/
├── app/
│   ├── main.py          # FastAPI server & proxy route (/v1/chat)
│   ├── context.py       # Immutable session lock (X-User-ID & X-User-Role)
│   ├── delimiter.py     # Per-request cryptographic boundary tagging
│   ├── guard.py         # Deterministic RBAC & BOLA policy engine
│   └── scrubber.py      # Outbound regex DLP secret scrubber
├── policies.json        # Declarative tool permissions & BOLA rules
├── test_attacks.py      # Automated security regression test suite
├── requirements.txt     # Project dependencies
└── README.md
```

---

## Quickstart

### 1. Set Up Environment & Install Dependencies

```bash
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Start the Proxy Server

```bash
uvicorn app.main:app --reload
```

* **Interactive Swagger UI:** `http://127.0.0.1:8000/docs`

---

## Running the Automated Security Suite

With the proxy server running, open a second terminal and run the attack simulation script:

```bash
.\venv\Scripts\python.exe test_attacks.py
```

### Expected Output

```text
=== Running latch-proxy Security Suite ===

[TEST 1] Authorized Self-Access (user_42 -> user_42): HTTP 200 | Expected: 200
[TEST 2] BOLA Cross-Tenant Hijack (user_42 -> admin_01): HTTP 403 | Rule: BOLA_CROSS_TENANT_ACCESS | Expected: 403
[TEST 3] Authorized Admin Override (role=admin):       HTTP 200 | Expected: 200
[TEST 4] Egress Secret Scrubber:                       HTTP 200 | Redacted: 2 secrets
         Scrubbed Output: "Here is the summary. Debug info: [REDACTED_OPENAI_OR_OPENROUTER_KEY] and [REDACTED_CREDENTIAL_ASSIGNMENT]"
```

---

## Configuration (Mock vs. Live Mode)

By default, `latch-proxy` runs in **Mock Mode** (`LATCH_MODE=mock`) so you can run all security and BOLA hijack simulations offline without an API key.

To connect a live upstream model via OpenRouter, create a `.env` file in the root directory:

```env
LATCH_MODE=live
OPENROUTER_API_KEY=your_api_key_here
UPSTREAM_MODEL=google/gemini-2.5-flash
```