"""Unit tests for DateShifter.

Covers:
- MM/DD/YYYY date shifting
- YYYY-MM-DD date shifting
- Format preservation after shift
- Age group preservation (pediatric, geriatric)
- Age clamping within group boundaries
- Session-deterministic (consistent) shifts
- Temporal order preservation
- Different sessions produce different shifts
"""

from __future__ import annotations

import uuid
from datetime import datetime

import pytest

from phi_redactor.masking.date_shifter import DateShifter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def session_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def fixed_session() -> str:
    """A stable session ID so tests that need determinism have a fixed anchor."""
    return "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture
def shifter(session_id: str) -> DateShifter:
    return DateShifter(session_id=session_id)


@pytest.fixture
def fixed_shifter(fixed_session: str) -> DateShifter:
    return DateShifter(session_id=fixed_session)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestShiftDateFormats:
    def test_shift_date_mm_dd_yyyy(self, shifter: DateShifter) -> None:
        """MM/DD/YYYY format is parsed and shifted without errors."""
        original = "03/15/1956"
        shifted = shifter.shift_date(original)

        # Must be parseable in the same format.
        parsed_shifted = datetime.strptime(shifted, "%m/%d/%Y")
        parsed_original = datetime.strptime(original, "%m/%d/%Y")

        # The shift should be exactly shift_days days.
        delta = (parsed_shifted - parsed_original).days
        assert delta == shifter.shift_days

    def test_shift_date_yyyy_mm_dd(self, shifter: DateShifter) -> None:
        """YYYY-MM-DD format is parsed and shifted correctly."""
        original = "1956-03-15"
        shifted = shifter.shift_date(original)

        parsed_shifted = datetime.strptime(shifted, "%Y-%m-%d")
        parsed_original = datetime.strptime(original, "%Y-%m-%d")

        delta = (parsed_shifted - parsed_original).days
        assert delta == shifter.shift_days

    def test_shift_date_preserves_mm_dd_yyyy_format(self, shifter: DateShifter) -> None:
        """Output format must match MM/DD/YYYY input format."""
        original = "01/01/2000"
        shifted = shifter.shift_date(original)

        # Verify the string matches MM/DD/YYYY structure.
        datetime.strptime(shifted, "%m/%d/%Y")  # raises if format is wrong

    def test_shift_date_preserves_yyyy_mm_dd_format(self, shifter: DateShifter) -> None:
        """Output format must match YYYY-MM-DD input format."""
        original = "2000-01-01"
        shifted = shifter.shift_date(original)

        datetime.strptime(shifted, "%Y-%m-%d")

    def test_shift_date_preserves_format_long_month(self, shifter: DateShifter) -> None:
        """'Month DD, YYYY' format survives a round-trip shift."""
        original = "March 15, 1956"
        shifted = shifter.shift_date(original)

        datetime.strptime(shifted, "%B %d, %Y")


class TestShiftAge:
    def test_shift_age_pediatric_stays_pediatric(self, shifter: DateShifter) -> None:
        """A pediatric age (2-12) must remain in the pediatric group after shifting."""
        age = 7
        shifted_age = shifter.shift_age(age)
        assert shifter.get_age_group(shifted_age) == "pediatric"

    def test_shift_age_geriatric_stays_geriatric(self, shifter: DateShifter) -> None:
        """A geriatric age (65-89) must remain geriatric after shifting."""
        age = 72
        shifted_age = shifter.shift_age(age)
        assert shifter.get_age_group(shifted_age) == "geriatric"

    def test_shift_age_young_adult_stays_young_adult(self, shifter: DateShifter) -> None:
        """A young adult age (18-39) must remain in the young_adult group."""
        age = 25
        shifted_age = shifter.shift_age(age)
        assert shifter.get_age_group(shifted_age) == "young_adult"

    def test_shift_age_clamps_lower_bound(self) -> None:
        """When the natural shift would push age below group minimum, clamp to minimum."""
        # Use a session that produces a large negative age shift.
        large_neg_shifter = DateShifter(session_id="x", age_shift_years=-5)
        age = 2  # Bottom of pediatric (2-12)
        shifted_age = large_neg_shifter.shift_age(age)
        # Must stay within pediatric bounds [2, 12).
        assert shifted_age >= 2
        assert shifted_age < 13
        assert large_neg_shifter.get_age_group(shifted_age) == "pediatric"

    def test_shift_age_clamps_upper_bound(self) -> None:
        """When the natural shift would push age above group maximum, clamp to maximum."""
        large_pos_shifter = DateShifter(session_id="x", age_shift_years=5)
        age = 12  # Top of pediatric range (exclusive upper is 13)
        # 12 is the highest year still in pediatric [2,13).
        shifted_age = large_pos_shifter.shift_age(age)
        assert shifted_age <= 12  # must not escape to adolescent (13+)
        assert large_pos_shifter.get_age_group(shifted_age) == "pediatric"

    def test_shift_age_returns_int(self, shifter: DateShifter) -> None:
        """shift_age must always return an integer."""
        result = shifter.shift_age(45)
        assert isinstance(result, int)


class TestSessionConsistency:
    def test_consistent_within_session(self) -> None:
        """Two DateShifter instances with the same session_id must produce identical shifts."""
        sid = "consistent-session-id-12345"
        shifter_a = DateShifter(session_id=sid)
        shifter_b = DateShifter(session_id=sid)

        assert shifter_a.shift_days == shifter_b.shift_days
        assert shifter_a.age_shift_years == shifter_b.age_shift_years

    def test_same_date_same_session_same_output(self) -> None:
        """The same date shifted twice under the same session must yield the same result."""
        sid = "repeat-test-session"
        s1 = DateShifter(session_id=sid)
        s2 = DateShifter(session_id=sid)

        original = "06/15/1975"
        assert s1.shift_date(original) == s2.shift_date(original)


class TestTemporalOrderPreservation:
    def test_temporal_order_preserved_date1_before_date2(
        self, shifter: DateShifter
    ) -> None:
        """If date1 < date2, shifted_date1 must still be <= shifted_date2."""
        date1 = "01/10/2020"
        date2 = "03/15/2020"
        assert shifter.preserves_temporal_order(date1, date2)

    def test_temporal_order_preserved_date2_before_date1(
        self, shifter: DateShifter
    ) -> None:
        """Temporal order is preserved regardless of which date is earlier."""
        date1 = "12/31/2025"
        date2 = "01/01/2025"
        assert shifter.preserves_temporal_order(date1, date2)

    def test_temporal_order_equal_dates(self, shifter: DateShifter) -> None:
        """Equal dates must remain equal after shifting."""
        date = "07/04/1990"
        assert shifter.preserves_temporal_order(date, date)


class TestDifferentSessionsDifferentShifts:
    def test_different_sessions_different_offsets(self) -> None:
        """Two randomly generated session IDs should (very likely) produce different offsets."""
        sid_a = str(uuid.uuid4())
        sid_b = str(uuid.uuid4())
        s_a = DateShifter(session_id=sid_a)
        s_b = DateShifter(session_id=sid_b)

        # It is astronomically unlikely for two random UUIDs to yield the same 730-day offset.
        assert s_a.shift_days != s_b.shift_days

    def test_explicit_different_shift_days(self) -> None:
        """Explicit shift_days values must be honoured for each instance."""
        s1 = DateShifter(session_id="s", shift_days=100)
        s2 = DateShifter(session_id="s", shift_days=-200)

        original = "01/01/2000"
        shifted1 = s1.shift_date(original)
        shifted2 = s2.shift_date(original)

        assert shifted1 != shifted2

        parsed1 = datetime.strptime(shifted1, "%m/%d/%Y")
        parsed0 = datetime.strptime(original, "%m/%d/%Y")
        assert (parsed1 - parsed0).days == 100
