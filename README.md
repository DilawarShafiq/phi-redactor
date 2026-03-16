<p align="center">
  <h1 align="center">phi-redactor</h1>
  <p align="center">
    <strong>HIPAA-native PHI redaction proxy for AI/LLM interactions</strong>
  </p>
  <p align="center">
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
    <a href="https://github.com/dilawar-gopang/phi-redactor/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-green.svg" alt="License"></a>
    <a href="https://github.com/dilawar-gopang/phi-redactor/actions"><img src="https://img.shields.io/badge/CI-passing-brightgreen.svg" alt="CI"></a>
    <a href="https://github.com/dilawar-gopang/phi-redactor/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/PHI-Minimization%20Proxy-orange.svg" alt="PHI Minimization"></a>
  </p>
</p>

---

**phi-redactor** is an open-source, drop-in PHI masking proxy that sits between your healthcare AI applications and LLM providers (OpenAI, Anthropic). It automatically detects and pseudonymizes all 18 HIPAA PHI identifier categories in real-time, then restores original values locally — so **PHI never leaves your infrastructure in its original form**.

> **Compliance notice:** phi-redactor performs *semantic pseudonymization* — replacing real identifiers with clinically coherent synthetic ones. This is a PHI minimization and risk-reduction technique, **not** HIPAA de-identification under the Safe Harbor method (45 CFR §164.514(b)). Healthcare organizations must have a Business Associate Agreement (BAA) with their LLM provider and should consult legal counsel regarding their compliance posture. See [Compliance Posture](#compliance-posture) below.

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
| PHI leaks to cloud LLMs | Transparent proxy masks all 18 HIPAA identifiers |
| Inconsistent fake data | Semantic masking generates clinically coherent replacements |
| No audit trail | Tamper-evident hash-chain audit log for every redaction |
| Complex integration | Zero code changes -- just change your base URL |
| Multi-turn context loss | Encrypted vault preserves mappings across conversation turns |

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

phi-redactor is a **PHI minimization and risk-reduction proxy**. Understanding what it does — and does not — provide legally is essential before deployment in a healthcare context.

### What phi-redactor does

- Detects all 18 HIPAA PHI identifier categories and replaces them with clinically coherent synthetic values before forwarding requests to an LLM provider
- Ensures original PHI is never transmitted in plaintext to a third-party API
- Maintains an encrypted, tamper-evident audit trail of all redaction activity
- Preserves clinical context so the LLM can reason effectively (unlike `[REDACTED]` approaches)

### What phi-redactor does NOT do

- **It does not constitute HIPAA de-identification.** Under the Safe Harbor method (45 CFR §164.514(b)(2)), all 18 identifiers must be *removed*, not replaced. Sending a synthetic name and date of birth to an external LLM means the data still contains identifiers — they are just pseudonymous, not absent.
- **It does not eliminate the need for a BAA.** Any healthcare organization sending data (even pseudonymized) to OpenAI, Anthropic, or any other cloud LLM provider must have a signed Business Associate Agreement with that provider.
- **It is not a substitute for legal counsel.** Compliance decisions in covered-entity or business-associate contexts require your legal and privacy team.

### Recommended deployment posture

1. Execute a BAA with your LLM provider
2. Deploy phi-redactor as a defense-in-depth layer that minimizes PHI exposure in transit
3. Use the audit trail for breach notification support and internal compliance documentation
4. Consult a HIPAA compliance officer or attorney before making de-identification claims to patients, auditors, or OCR

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue first to discuss what you'd like to change.

---

<p align="center">
  Built for healthcare AI developers who take HIPAA seriously.
</p>
