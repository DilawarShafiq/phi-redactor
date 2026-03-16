# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-03-17

### Changed

- Repositioned compliance model: phi-redactor now explicitly implements the HIPAA **§164.514(c) surrogate code provision** — synthetic tokens are not derived from individual data and cannot be reversed without the separately secured Fernet key
- Compliance report title updated from "Safe Harbor" to "§164.514(c) Surrogate Code Compliance Report"
- `generate_safe_harbor()` refactored into `generate_attestation()` with full §164.514(c) and Expert Determination documentation; backward-compatible alias retained
- README rewritten to lead with the cryptographic privacy guarantee and §164.514(c) statutory grounding
- Removed misleading "HIPAA Safe Harbor" badge; replaced with accurate "PHI Minimization Proxy" badge
- Added Compliance Posture section to README with comparison table vs Safe Harbor
- SECURITY.md updated to accurately describe surrogate code architecture

### Added

- Compliance report now includes `surrogate_code_requirements` attestation block documenting satisfaction of both §164.514(c) statutory requirements
- Compliance report includes `expert_determination_pathway` section for statistician briefings
- New compliance check: `surrogate_code_164_514_c` — verifies architectural compliance with §164.514(c) in every generated report
- `statutory_reference` and `expert_determination_ready` fields in report metadata
- pyproject.toml keywords updated to include `pseudonymization`, `164-514-c`, `surrogate-code`, `expert-determination`

## [0.1.0] - 2026-02-27

### Added

- PHI detection engine with all 18 HIPAA identifiers using Presidio + spaCy
- Semantic masking with deterministic, identity-preserving fake data
- Encrypted vault (Fernet) for PHI-to-mask mappings with session isolation
- Tamper-evident audit trail with SHA-256 hash chains
- FastAPI reverse proxy with Anthropic and OpenAI adapters
- Streaming support for LLM responses with real-time re-identification
- Click-based CLI for session management, vault stats, and Safe Harbor reports
- Real-time monitoring dashboard
- FHIR R4 and HL7v2 recognizers via plugin system
- CI pipeline for Python 3.11, 3.12, 3.13
- Comprehensive test suite (detection, masking, vault, proxy, compliance)

[0.1.1]: https://github.com/DilawarShafiq/phi-redactor/releases/tag/v0.1.1
[0.1.0]: https://github.com/DilawarShafiq/phi-redactor/releases/tag/v0.1.0