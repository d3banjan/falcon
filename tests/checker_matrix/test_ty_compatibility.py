"""Verify ty uses the checker overlay for supported modules."""

from pathlib import Path

from tests.conftest import ty_check

CVE_FIXTURE = Path(__file__).parent.parent / "fixtures" / "fix_cve_downstream_wrappers.py"
SOURCE_CVE_FIXTURE = (
    Path(__file__).parent.parent / "fixtures" / "fix_cve_source_direct_pickle.py"
)


def test_ty_detects_cve_wrapper_stubs() -> None:
    """ty catches overlay-backed CVE wrapper stubs.

    ty currently reports the non-marshal fixture flows plus raw-input errors. It
    resolves stdlib marshal before the local overlay, so marshal is tracked as a
    compatibility gap rather than counted as validated under ty.
    """
    assert CVE_FIXTURE.exists(), f"Fixture not found: {CVE_FIXTURE}"
    rc, output = ty_check(CVE_FIXTURE)
    assert rc != 0, f"Expected ty failure but got exit 0. Output:\n{output}"
    assert output.count("error[invalid-assignment]") >= 34, (
        f"Expected broad Unsafe coverage in ty output but got:\n{output}"
    )
    assert "marshal_value" not in output, (
        "ty unexpectedly started honoring the marshal overlay; update coverage docs"
    )


def test_ty_detects_source_shaped_direct_pickle_cves() -> None:
    """ty catches direct pickle calls in source-shaped CVE fixtures."""
    assert SOURCE_CVE_FIXTURE.exists(), f"Fixture not found: {SOURCE_CVE_FIXTURE}"
    rc, output = ty_check(SOURCE_CVE_FIXTURE)
    assert rc != 0, f"Expected ty failure but got exit 0. Output:\n{output}"
    assert output.count("error[invalid-assignment]") >= 9, (
        f"Expected source-shaped Unsafe coverage in ty output but got:\n{output}"
    )
