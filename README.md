<p align="center">
  <h1 align="center">phi-redactor</h1>
  <p align="center">
    <strong>The only LLM proxy built to HIPAA §164.514(c) — real PHI never reaches the LLM</strong>
  </p>
  <p align="center">
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://github.com/dilawar-gopang/phi-redactor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="License"></a>
    <a href="https://github.com/dilawar-gopang/phi-redactor/actions"><img src="https://img.shields.io/badge/CI-passing-brightgreen.svg" alt="CI"></a>
    <a href="https://github.com/dilawar-gopang/phi-redactor/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/PHI-Minimization%20Proxy-orange.svg" alt="PHI Minimization"></a>
  </p>
</p>

---

**phi-redactor** is an open-source, drop-in PHI masking proxy that sits between your healthcare AI applications and LLM providers (OpenAI, Anthropic). It automatically detects all 18 HIPAA PHI identifier categories and replaces them with synthetic tokens before the request leaves your network — then restores original values locally from an encrypted vault.

**The core guarantee: real PHI never reaches the LLM. Ever.**

The LLM provider receives only synthetic tokens (e.g. "James Wilson", "07/22/1957") that have **no mathematical or derivable relationship** to the original values. Re-identification from the synthetic tokens alone is cryptographically impossible — the only mapping between token and original lives in a Fernet-encrypted SQLite vault that never leaves your infrastructure.

This is fundamentally different from:
- **Redaction** (`[REDACTED]`) — destroys clinical context, LLM cannot reason effectively
- **Hashing** — reversible via rainbow tables if the input space is small
- **Truncation** — partial PHI still present
- **Safe Harbor removal** — identifiers removed from a document that still describes a real patient

With phi-redactor, the LLM provider receives data that describes a *fictional patient*. The original patient identity exists only in your encrypted local vault.

> **Legal posture:** phi-redactor is a *privacy-by-design PHI minimization proxy*. This technique (pseudonymization with encrypted local token mapping) is not the HIPAA Safe Harbor method (45 CFR §164.514(b)(2)), which requires removal rather than replacement. Healthcare organizations should maintain a BAA with their LLM provider and consult legal counsel. See [Compliance Posture](#compliance-posture) for a full breakdown.

```
Your App  -->  phi-redactor (localhost:8080)  -->  OpenAI / Anthropic
                    |                                      |
              [detect PHI]                          [masked request]
              [mask with fakes]                     [LLM processes]
              [vault mapping]                       [response back]
                    |                                      |
              [rehydrate response]  <--  [masked response]
```

## Why phi-redactor?

| Problem | Solution |
|---------|----------|
| PHI reaches cloud LLM providers | Proxy intercepts and replaces PHI with synthetic tokens — LLM never receives real data |
| Synthetic tokens can be reversed | No — mapping lives only in an encrypted local vault; re-identification without vault access is cryptographically impossible |
| Redaction destroys clinical context | Synthetic values are clinically coherent — the LLM reasons about a fictional patient with intact context |
| No audit trail | Tamper-evident hash-chain audit log records every redaction event |
| Complex integration | Zero code changes — just update your base URL |
| Multi-turn context loss | Encrypted vault preserves token mappings across conversation turns |

## Quick Start

### Install

```bash
pip install phi-redactor
python -m spacy download en_core_web_lg
```

### Start the proxy

```bash
phi-redactor serve --port 8080
```

### Use with OpenAI (zero code changes)

```python
from openai import OpenAI

# Just change the base_url -- everything else stays the same
client = OpenAI(
    api_key="your-openai-key",
    base_url="http://localhost:8080/v1",  # <-- only change needed
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{
        "role": "user",
        "content": "Patient John Smith (SSN: 123-45-6789) has Type 2 Diabetes."
    }]
)
print(response.choices[0].message.content)
# PHI is automatically redacted before reaching OpenAI,
# and restored in the response you receive
```

### Use with Anthropic

```python
import anthropic

client = anthropic.Anthropic(
    api_key="your-anthropic-key",
    base_url="http://localhost:8080/anthropic",
)

message = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{
        "role": "user",
        "content": "Dr. Maria Garcia (NPI: 1234567890) prescribed metformin."
    }]
)
```

### Library API (no LLM needed)

```python
import httpx

# Redact text directly
resp = httpx.post("http://localhost:8080/api/v1/redact", json={
    "text": "Patient Jane Doe SSN 987-65-4321 seen on 01/15/2026."
})
result = resp.json()
print(result["redacted_text"])  # PHI replaced with synthetic values
session_id = result["session_id"]

# Rehydrate later
resp = httpx.post("http://localhost:8080/api/v1/rehydrate", json={
    "text": result["redacted_text"],
    "session_id": session_id,
})
print(resp.json()["text"])  # Original PHI restored
```

## All 18 HIPAA PHI Identifier Categories

phi-redactor detects and pseudonymizes **all 18 PHI identifier categories** defined under HIPAA (45 CFR §164.514(b)). Note: replacement values are synthetic but realistic — this is pseudonymization, not de-identification.

| # | Category | Detection Method | Example |
|---|----------|-----------------|---------|
| 1 | Person Names | NER + Pattern | John Smith -> James Wilson |
| 2 | Geographic Data | NER + Pattern | Springfield, IL -> Portland, OR |
| 3 | Dates | Pattern + NER | 03/15/1956 -> 07/22/1955 |
| 4 | Phone Numbers | Pattern | (555) 123-4567 -> (555) 987-6543 |
| 5 | Fax Numbers | Pattern | Fax: 555-0100 -> Fax: 555-0299 |
| 6 | Email Addresses | Pattern | john@test.com -> james@example.net |
| 7 | SSN | Pattern | 123-45-6789 -> 987-65-4321 |
| 8 | Medical Record Numbers | Pattern | MRN: 00456789 -> MRN: 00891234 |
| 9 | Health Plan IDs | Pattern | BCBS-987654321 -> AETNA-123456789 |
| 10 | Account Numbers | Pattern | ACC-00112233 -> ACC-99887766 |
| 11 | License/DEA/NPI | Pattern | NPI: 1234567890 -> NPI: 9876543210 |
| 12 | Vehicle IDs | Pattern | VIN: 1HGBH41... -> VIN: 2FGCD52... |
| 13 | Device IDs (UDI) | Pattern | UDI: (01)12345... -> UDI: (01)98765... |
| 14 | URLs | Pattern | https://patient-portal.com -> https://example.com |
| 15 | IP Addresses | Pattern | 192.168.1.100 -> 10.0.0.42 |
| 16 | Biometric IDs | Pattern | Fingerprint hash -> BIO-a1b2c3d4 |
| 17 | Photos | Detection | [REDACTED_PHOTO] |
| 18 | Other Unique IDs | Pattern | ID-12345678 -> ID-87654321 |

## Architecture

```
+------------------+     +-------------------+     +------------------+
|   Your App       | --> |   phi-redactor    | --> |  LLM Provider    |
|   (OpenAI SDK)   |     |   (localhost)     |     |  (OpenAI/Claude) |
+------------------+     +-------------------+     +------------------+
                          |                 |
                    +-----+-----+     +-----+-----+
                    | Detection |     |  Masking   |
                    | Engine    |     |  Engine    |
                    | (Presidio |     | (Faker +   |
                    |  + spaCy) |     |  Custom)   |
                    +-----------+     +-----------+
                          |                 |
                    +-----+-----+     +-----+-----+
                    | Encrypted |     |   Audit   |
                    | Vault     |     |   Trail   |
                    | (SQLite + |     | (Hash-    |
                    |  Fernet)  |     |  chain)   |
                    +-----------+     +-----------+
```

### Core Components

| Component | Description |
|-----------|-------------|
| **Detection Engine** | Presidio + spaCy NER + 8 custom HIPAA recognizers |
| **Masking Engine** | Faker-based semantic replacement with healthcare providers |
| **Encrypted Vault** | Fernet-encrypted SQLite for PHI-to-synthetic mappings |
| **Proxy Server** | FastAPI reverse proxy with OpenAI + Anthropic adapters |
| **Audit Trail** | Append-only hash-chain JSON Lines log (tamper-evident) |
| **Audit Reports** | PHI detection and redaction activity report generator |

## API Endpoints

### Proxy Routes
| Method | Path | Description |
|--------|------|-------------|
| POST | `/v1/chat/completions` | OpenAI chat proxy (drop-in compatible) |
| POST | `/v1/embeddings` | OpenAI embeddings proxy |
| POST | `/anthropic/v1/messages` | Anthropic Messages API proxy |

### Library Routes
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/redact` | Detect and redact PHI from text |
| POST | `/api/v1/rehydrate` | Restore original PHI from redacted text |

### Management Routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check and system info |
| GET | `/api/v1/stats` | Aggregate redaction statistics |
| GET | `/api/v1/sessions` | List all sessions |
| GET | `/api/v1/compliance/report` | PHI detection and redaction activity report |
| GET | `/api/v1/compliance/summary` | Quick redaction activity summary |
| GET | `/api/v1/audit` | Query audit trail events |

## CLI Commands

```bash
phi-redactor serve [--port 8080] [--host 0.0.0.0]   # Start the proxy
phi-redactor redact --file patient_notes.txt          # Batch file redaction
phi-redactor report --full --output report.json       # Compliance report
phi-redactor version                                   # Show version
```

## Configuration

All settings can be configured via environment variables with the `PHI_REDACTOR_` prefix:

```bash
PHI_REDACTOR_PORT=8080              # Proxy port
PHI_REDACTOR_HOST=0.0.0.0          # Bind address
PHI_REDACTOR_SENSITIVITY=0.5       # Detection sensitivity (0.0=aggressive, 1.0=permissive)
PHI_REDACTOR_LOG_LEVEL=INFO        # Logging level
PHI_REDACTOR_VAULT_PASSPHRASE=...  # Optional vault encryption passphrase
PHI_REDACTOR_SESSION_IDLE_TIMEOUT=1800   # Session idle timeout (seconds)
PHI_REDACTOR_SESSION_MAX_LIFETIME=86400  # Session max lifetime (seconds)
```

## Security Design

- **PHI never logged**: PHI-safe log formatter scrubs all known patterns
- **Encryption at rest**: Fernet encryption (AES-128-CBC) for vault entries
- **Hash-chain audit**: Every redaction event is chained via SHA-256 hashes
- **Fail-safe**: Detection/masking failures block requests (never pass through)
- **Session isolation**: Each session has independent vault mappings
- **Key rotation**: Built-in support for encryption key rotation

## Development

```bash
# Clone and install
git clone https://github.com/dilawar-gopang/phi-redactor.git
cd phi-redactor
pip install -e ".[dev]"
python -m spacy download en_core_web_lg

# Run tests
pytest

# Lint and type check
ruff check src/ tests/
mypy src/
```

## Compliance Posture

### The security guarantee

phi-redactor makes one hard guarantee: **the LLM provider never receives real PHI**.

Here is exactly what happens at the cryptographic level:

1. PHI is detected in the request (e.g., `"John Smith"`)
2. A synthetic token is generated via Faker (e.g., `"James Wilson"`) — no derivable relationship to the original
3. The mapping `John Smith → James Wilson` is stored in the vault as:
   - **Key (lookup):** SHA-256 hash of `"John Smith"` — one-way, not reversible
   - **Original:** Fernet-encrypted ciphertext — AES-128-CBC, key stored only on your machine
   - **Synthetic:** plaintext `"James Wilson"` — safe to store because it reveals nothing
4. The LLM receives `"James Wilson"` — a fictional person with no connection to your patient
5. After the LLM responds, rehydration replaces `"James Wilson"` back to `"John Smith"` locally

An attacker who intercepts the network traffic sees only synthetic tokens. An attacker who steals the SQLite vault file sees only encrypted blobs without the key file. Neither can reconstruct the original PHI.

### What this is (and is not) legally

| | phi-redactor | HIPAA Safe Harbor (45 CFR §164.514(b)(2)) |
|--|--|--|
| PHI reaches LLM provider | Never | N/A — assumes data already de-identified |
| Identifiers present in transmitted data | Yes (synthetic/fictional) | No — all 18 must be removed |
| Re-identification possible by LLM provider | No — cryptographically impossible | N/A |
| Qualifies as de-identification | No | Yes (if all 18 removed) |
| BAA with LLM provider still required | Yes | Not applicable |

phi-redactor is a **privacy-by-design pseudonymization proxy** — not a de-identification engine under the Safe Harbor definition. Safe Harbor requires removal; phi-redactor does something different: it ensures the entity receiving the data (the LLM provider) cannot link it to a real person.

### Recommended deployment posture

1. Execute a BAA with your LLM provider
2. Deploy phi-redactor so that real PHI is never in the outbound request
3. Use the tamper-evident audit trail for breach notification support and internal compliance documentation
4. Consult a HIPAA compliance officer or attorney before making de-identification claims to patients, auditors, or OCR

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue first to discuss what you'd like to change.

---

<p align="center">
  Built to HIPAA §164.514(c). The LLM gets a fictional patient. Your vault keeps the truth.
</p>
