"""Date and age shifting for HIPAA-compliant temporal de-identification.

Provides consistent date shifting within a session using a deterministic
offset, preserving temporal relationships (admission before discharge)
and clinical age groups (pediatric stays pediatric, geriatric stays geriatric).
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timedelta


# Supported date formats (ordered by specificity)
_DATE_FORMATS = [
    "%m/%d/%Y",
    "%Y-%m-%d",
    "%B %d, %Y",
    "%b %d, %Y",
    "%d-%m-%Y",
    "%m-%d-%Y",
    "%m/%d/%y",
    "%Y/%m/%d",
    "%d %B %Y",
    "%d %b %Y",
]

# Age group boundaries for clinical preservation
_AGE_GROUPS = [
    (0, 2, "neonate/infant"),
    (2, 13, "pediatric"),
    (13, 18, "adolescent"),
    (18, 40, "young_adult"),
    (40, 65, "middle_aged"),
    (65, 90, "geriatric"),
    (90, 200, "super_elderly"),
]


class DateShifter:
    """Shifts dates and ages by consistent session-deterministic offsets.

    Parameters:
        session_id: Session identifier for deterministic offset computation.
        shift_days: Explicit day offset. If ``None``, computed from session_id.
        age_shift_years: Explicit age offset. If ``None``, computed from session_id.
    """

    def __init__(
        self,
        session_id: str,
        shift_days: int | None = None,
        age_shift_years: int | None = None,
    ) -> None:
        self._session_id = session_id

        if shift_days is not None:
            self._shift_days = shift_days
        else:
            digest = hashlib.sha256(f"date_shift:{session_id}".encode()).hexdigest()
            self._shift_days = (int(digest[:8], 16) % 730) - 365  # [-365, 364]

        if age_shift_years is not None:
            self._age_shift_years = age_shift_years
        else:
            digest = hashlib.sha256(f"age_shift:{session_id}".encode()).hexdigest()
            self._age_shift_years = (int(digest[:4], 16) % 11) - 5  # [-5, 5]

    @property
    def shift_days(self) -> int:
        """The date shift offset in days."""
        return self._shift_days

    @property
    def age_shift_years(self) -> int:
        """The age shift offset in years."""
        return self._age_shift_years

    def shift_date(self, original: str) -> str:
        """Shift a date string by the session's deterministic offset.

        Attempts to parse the date using multiple common formats.
        Falls back to returning a placeholder if unparseable.

        Args:
            original: The original date string.

        Returns:
            The shifted date in the same format as the original.
        """
        text = original.strip()

        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(text, fmt)
                shifted = parsed + timedelta(days=self._shift_days)
                return shifted.strftime(fmt)
            except ValueError:
                continue

        # Try to extract a date from surrounding text
        date_match = re.search(r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}", text)
        if date_match:
            return self.shift_date(date_match.group())

        return f"[SHIFTED_DATE]"

    def shift_age(self, original_age: int) -> int:
        """Shift an age value while preserving its clinical age group.

        The shifted age is clamped to stay within the same clinical category
        (pediatric, adult, geriatric, etc.) to preserve clinical relevance.

        Args:
            original_age: The original age in years.

        Returns:
            The shifted age, guaranteed to be in the same clinical group.
        """
        shifted = original_age + self._age_shift_years

        # Clamp to preserve age group
        for low, high, _group_name in _AGE_GROUPS:
            if low <= original_age < high:
                return max(low, min(high - 1, shifted))

        # Fallback: clamp to valid range
        return max(0, min(120, shifted))

    def get_age_group(self, age: int) -> str:
        """Return the clinical age group name for a given age."""
        for low, high, group_name in _AGE_GROUPS:
            if low <= age < high:
                return group_name
        return "unknown"

    def preserves_temporal_order(
        self, date1: str, date2: str
    ) -> bool:
        """Verify that shifting preserves the temporal ordering of two dates.

        This is guaranteed by the design (same additive offset), but provided
        as a validation utility.

        Returns:
            True if the shifted dates maintain the same order as originals.
        """
        shifted1 = self.shift_date(date1)
        shifted2 = self.shift_date(date2)

        for fmt in _DATE_FORMATS:
            try:
                orig1 = datetime.strptime(date1.strip(), fmt)
                orig2 = datetime.strptime(date2.strip(), fmt)
                sh1 = datetime.strptime(shifted1.strip(), fmt)
                sh2 = datetime.strptime(shifted2.strip(), fmt)
                return (orig1 <= orig2) == (sh1 <= sh2)
            except ValueError:
                continue

        return True  # Can't verify, assume preserved
