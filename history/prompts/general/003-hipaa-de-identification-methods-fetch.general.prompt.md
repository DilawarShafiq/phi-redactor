---
id: "003"
title: HIPAA De-Identification Methods URL Fetch
stage: general
date: 2026-03-17
surface: agent
model: claude-sonnet-4-6
feature: none
branch: main
user: TechTiesIbrahim
command: WebFetch brickergraydon.com HIPAA de-identification 164.514(a)
labels: ["hipaa","de-identification","safe-harbor","expert-determination","phi","pseudonymization"]
links:
  spec: null
  ticket: null
  adr: null
  pr: null
files:
  - none
tests:
  - none
---

## Prompt

Fetch the content from this URL and return the full text: https://www.brickergraydon.com/insights/resources/key/HIPAA-Privacy-Regulations-Other-Requirements-Relating-to-Uses-and-Disclosures-of-Protected-Health-Information-De-Identification-of-Protected-Health-Information-164-514-a#:~:text=Alternatively%2C%20covered%20entities%20may%20choose%20to%20use,Privacy%20Rule's%20safe%20harbor%20method%20for%20de%2Didentification.

Return the full text content, especially anything about Expert Determination, Safe Harbor, pseudonymization, and de-identification methods under HIPAA.

## Response snapshot

Retrieved and returned full text from the Bricker Graydon HIPAA 164.514(a) resource page covering:

**Two De-Identification Methods:**
1. Expert Determination — qualified professional applies "generally accepted statistical and scientific principles and methods" to certify "very small risk" of re-identification.
2. Safe Harbor — prescriptive removal of all 18 enumerated PHI identifier categories plus no residual knowledge of re-identification possibility.

**Safe Harbor 18 Identifiers:** Names, street addresses, SSNs, email addresses, phone/fax numbers, medical record numbers, health plan beneficiary numbers, account numbers, certificate/license numbers, vehicle identifiers, device serial numbers, web URLs, IP addresses, biometric identifiers (fingerprints, voiceprints), full-face photographs, and any other unique identifying number/characteristic/code.

**Geographic/Temporal Rules:**
- 3-digit ZIP codes retained only if population > 20,000; 17 ZIPs must become "000": 036, 059, 063, 102, 203, 556, 692, 790, 821, 823, 830, 831, 878, 879, 884, 890, 893
- Ages 90+ aggregated to "90+"
- Dates retained at year level only

**Pseudonymization (Re-identification Code Provision):** Covered entities may assign surrogate codes enabling re-linkage if the code is not derived from or related to the individual's information — the HIPAA basis for pseudonymization.

**Comparison table** of Expert Determination vs Safe Harbor across approach, performer, threshold, flexibility, and documentation requirements provided.

## Outcome

- Impact: Research/reference — full HIPAA 164.514(a) de-identification regulatory text retrieved for project context
- Tests: none
- Files: none (read-only web fetch)
- Next prompts: Apply Safe Harbor identifier list to PHI redaction pipeline; implement ZIP code population threshold check; document pseudonymization token strategy
- Reflection: The 17 restricted ZIP prefixes and the age-90+ aggregation rule are operationally important details for the phi-redactor implementation that go beyond naive identifier removal.

## Evaluation notes (flywheel)

- Failure modes observed: none — page fetched successfully
- Graders run and results (PASS/FAIL): none
- Prompt variant (if applicable): none
- Next experiment (smallest change to try): Cross-reference with HHS official guidance at hhs.gov/hipaa/for-professionals/privacy/special-topics/de-identification
