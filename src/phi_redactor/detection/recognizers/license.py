"""Certificate / License Number recognizer for Presidio.

Detects professional license and certificate numbers including:

- **DEA numbers**: 2 letters followed by 7 digits (e.g., AB1234563).
- **NPI numbers**: 10-digit National Provider Identifier with Luhn check.
- **State license numbers**: Alphanumeric sequences near context words like
  "license #", "license number", "certificate number".

Entity type: ``LICENSE_NUMBER``
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer, RecognizerResult


class LicenseRecognizer(PatternRecognizer):
    """Detect certificate and license numbers (DEA, NPI, state licenses).

    Patterns:
        - ``dea_number``: Two letters + 7 digits.  Score 0.7 (high
          structural specificity).
        - ``npi_number``: Exactly 10 digits starting with 1 or 2.
          Score 0.5 (validated further by Luhn check).
        - ``state_license``: 1-3 letters + 5-10 digits with context.
          Score 0.3 (requires context boost).
    """

    PATTERNS = [
        Pattern(
            "dea_number",
            r"\b[A-HJ-NP-Z][A-Z9]\d{7}\b",
            0.7,
        ),
        Pattern(
            "npi_number",
            r"\b[12]\d{9}\b",
            0.5,
        ),
        Pattern(
            "state_license",
            r"\b[A-Z]{1,3}[-]?\d{5,10}\b",
            0.3,
        ),
    ]

    CONTEXT = [
        "license",
        "license #",
        "license number",
        "license no",
        "certificate",
        "certificate number",
        "certificate #",
        "dea",
        "dea number",
        "dea #",
        "npi",
        "npi number",
        "npi #",
        "national provider",
        "provider number",
        "registration number",
        "registration #",
        "medical license",
        "nursing license",
        "pharmacy license",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity="LICENSE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="en",
            name="LicenseRecognizer",
        )

    def validate_result(self, pattern_text: str) -> bool | RecognizerResult | None:
        """Apply additional validation for NPI numbers via Luhn check.

        The Luhn algorithm is the standard checksum for NPI validation.
        DEA and state license patterns pass through without extra validation.
        """
        # NPI validation: 10 digits starting with 1 or 2
        if len(pattern_text) == 10 and pattern_text.isdigit() and pattern_text[0] in ("1", "2"):
            return self._luhn_check(pattern_text)
        return True

    @staticmethod
    def _luhn_check(number: str) -> bool:
        """Validate a number using the Luhn algorithm.

        For NPI numbers, the check digit is the last digit, and the prefix
        80840 is prepended before computing the Luhn checksum per CMS rules.

        Args:
            number: The 10-digit NPI string.

        Returns:
            True if the Luhn checksum is valid.
        """
        # NPI Luhn: prefix with 80840 (US health industry) then validate
        prefixed = "80840" + number
        digits = [int(d) for d in prefixed]
        checksum = 0
        # Process from right to left
        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                doubled = digit * 2
                checksum += doubled - 9 if doubled > 9 else doubled
            else:
                checksum += digit
        return checksum % 10 == 0
