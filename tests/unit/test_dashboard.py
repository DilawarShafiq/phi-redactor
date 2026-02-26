"""Unit tests for the dashboard module."""
from __future__ import annotations
from pathlib import Path


def test_static_index_exists() -> None:
    """The dashboard static/index.html file must exist."""
    index = Path(__file__).resolve().parents[2] / "src" / "phi_redactor" / "dashboard" / "static" / "index.html"
    assert index.exists(), f"Dashboard index.html not found at {index}"


def test_static_index_contains_title() -> None:
    """The dashboard HTML should contain the expected title."""
    index = Path(__file__).resolve().parents[2] / "src" / "phi_redactor" / "dashboard" / "static" / "index.html"
    content = index.read_text(encoding="utf-8")
    assert "PHI Redactor Dashboard" in content


def test_dashboard_routes_importable() -> None:
    """Dashboard routes module should be importable."""
    from phi_redactor.dashboard import routes
    assert hasattr(routes, "router")
