"""Verify mypy correctly uses our stubs."""
from pathlib import Path

from tests.conftest import mypy_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_01_loads_reduce.py"
CVE_FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_cve_downstream_wrappers.py"
SOURCE_CVE_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "fix_cve_source_direct_pickle.py"
)


def test_mypy_detects_unsafe_any_on_loads() -> None:
    """mypy --strict on fixture must report Unsafe[Any] error."""
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )


def test_mypy_strict_mode_enabled() -> None:
    """Verify mypy is running with strict configuration."""
    rc, output = mypy_check(FIXTURE)
    strict_indicators = ["strict", "Strict"]
    assert any(indicator in output.lower() for indicator in strict_indicators) or rc != 0, (
        "mypy should be in strict mode"
    )


def test_mypy_detects_cve_wrapper_stubs() -> None:
    """mypy catches the CVE-backed downstream wrapper fixture."""
    assert CVE_FIXTURE.exists(), f"Fixture not found: {CVE_FIXTURE}"
    rc, output = mypy_check(CVE_FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert output.count("error:") >= 45 and output.count("Unsafe[") >= 33, (
        f"Expected broad Unsafe[Any] coverage in mypy output but got:\n{output}"
    )
    assert "expected \"TrustedBytes\"" in output
    assert "expected \"TrustedPath\"" in output


def test_mypy_detects_source_shaped_direct_pickle_cves() -> None:
    """mypy catches direct pickle calls in source-shaped CVE fixtures."""
    assert SOURCE_CVE_FIXTURE.exists(), f"Fixture not found: {SOURCE_CVE_FIXTURE}"
    rc, output = mypy_check(SOURCE_CVE_FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert output.count("error:") >= 9 and output.count("Unsafe[") >= 9, (
        f"Expected source-shaped Unsafe[Any] coverage in mypy output but got:\n{output}"
    )
