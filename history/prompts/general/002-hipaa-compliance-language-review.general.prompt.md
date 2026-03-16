---
id: 002
title: HIPAA Compliance Language Review
stage: general
date: 2026-03-17
surface: agent
model: claude-sonnet-4-6
feature: none
branch: main
user: TechTiesIbrahim
command: review compliance claims vs critic feedback
labels: ["hipaa","compliance","legal","documentation","review"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files:
  - README.md
  - SECURITY.md
tests:
  - none
---

## Prompt

is this project same?
I wrote:
US healthcare organizations want to use LLMs but they can't risk PHI leaving their network. We built phi-redactor, an open source HIPAA compliant proxy that sits between your application and LLM providers like OpenAI or Anthropic. How it works: Your app sends a request → phi-redactor intercepts it. It automatically detects all 18 HIPAA Safe Harbor identifiers. Identifiers are replaced with clinically coherent synthetic values. Example: "John Smith, DOB 03/15/1956" → "Robert Chen, DOB 07/22/1957". Not [REDACTED]. The sanitized request is sent to the LLM. The response is rehydrated with the original values before returning to your app. Why semantic masking matters: Simple redaction destroys clinical context. When text becomes [REDACTED], the model loses the information it needs to reason effectively. phi-redactor preserves the medical meaning while eliminating PHI exposure. Under the hood: Hybrid detection engine: Presidio + spaCy NER + 8 custom healthcare recognizers. FHIR / HL7 native parsing — not just regex on free text. Encrypted vault with session-scoped identity consistency across multi-turn conversations. Tamper-evident hash-chain audit trail for compliance teams. Fail-safe architecture: errors block requests instead of risking data leakage. Real-time monitoring dashboard. 256 automated tests covering detection, security, compliance, and proxy behavior. Zero integration friction. Integration requires one change update your LLM base URL. No SDK wrappers. No code refactoring. pip install phi-redactor. Open source | Apache 2.0 | Python.

Someone criticized:
What you have described - replacing real identifiers with fake but realistic ones - is technically known as pseudonymization or tokenization. Under HIPAA, this is explicitly not considered de-identification. The presence of a name, even a fake one, immediately disqualifies the data from Safe Harbor status. An OCR investigator will look at this file, see a field with "Robert Chen, DOB 07/22/1957", and stop reading. The investigation is over. The fine is coming.

Your job is to review https://github.com/DilawarShafiq/phi-redactor which was based on my input.

## Response snapshot

Confirmed: local project IS the same as the GitHub repo (git history shows merges from DilawarShafiq/phi-redactor).

Critic's point is legally correct on the Safe Harbor framing:
- README.md contains a "HIPAA-Safe Harbor" badge citing 45 CFR §164.514(b)(2)
- SECURITY.md explicitly claims the tool implements the Safe Harbor method
- The masking table shows name→name replacement labeled as Safe Harbor compliant
- This is legally wrong: Safe Harbor requires removal, not replacement

Engineering is solid (Presidio + spaCy + custom recognizers, session vault, fail-safe blocking, hash-chain audit). The problem is documentation/marketing — not code.

Proposed fix: docs-only changes to README.md and SECURITY.md replacing "Safe Harbor de-identification" claims with accurate "semantic pseudonymization / PHI minimization proxy" language, plus a Compliance Posture section explaining BAA pathway.

## Outcome

- ✅ Impact: Identified legally hazardous HIPAA Safe Harbor claims in README and SECURITY.md that misrepresent the tool's compliance posture
- 🧪 Tests: none run
- 📁 Files: README.md, SECURITY.md identified as requiring documentation fixes
- 🔁 Next prompts: Fix compliance language in README.md and SECURITY.md; add Compliance Posture section
- 🧠 Reflection: The engineering is correct; the marketing/legal framing is what needs updating. The tool provides PHI minimization and risk reduction, not HIPAA de-identification.

## Evaluation notes (flywheel)

- Failure modes observed: none
- Graders run and results (PASS/FAIL): n/a
- Prompt variant (if applicable): none
- Next experiment (smallest change to try): Rewrite Safe Harbor claims in README.md first, then SECURITY.md
