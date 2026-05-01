"""Verify pyright correctly uses our stubs."""
from pathlib import Path

from tests.conftest import pyright_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_01_loads_reduce.py"
CVE_FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_cve_downstream_wrappers.py"


def test_pyright_detects_unsafe_any_on_loads() -> None:
    """pyright on fixture must report Unsafe[Any] error."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = pyright_check(FIXTURE)
    assert rc != 0, f"Expected pyright failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in pyright output but got:\n{output}"
    )


def test_pyright_strict_mode_enabled() -> None:
    """Verify pyright is running with strict configuration."""
    rc, output = pyright_check(FIXTURE)
    strict_indicators = ["strict", "error"]
    assert any(indicator in output.lower() for indicator in strict_indicators) or rc != 0, (
        "pyright should be in strict mode"
    )


def test_pyright_report_any_errors() -> None:
    """Verify pyright catches Any type issues."""
    rc, output = pyright_check(FIXTURE)
    assert rc != 0, "pyright should flag errors on unsafe pickle usage"
    assert "Unsafe" in output, "pyright should report Unsafe type issues"


def test_pyright_detects_cve_wrapper_stubs() -> None:
    """pyright catches the CVE-backed downstream wrapper fixture."""
    assert CVE_FIXTURE.exists(), f"Fixture not found: {CVE_FIXTURE}"
    rc, output = pyright_check(CVE_FIXTURE)
    assert rc != 0, f"Expected pyright failure but got exit 0. Output:\n{output}"
    assert output.count("error:") >= 23 and output.count("Unsafe[") >= 23, (
        f"Expected broad Unsafe[Any] coverage in pyright output but got:\n{output}"
    )
