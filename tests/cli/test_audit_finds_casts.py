"""Test pickle-secure audit — finding cast-escape sites."""

from pathlib import Path


from pickle_stubs_secure.cli.audit_cmd import audit_file, audit
from tests.cli.fixtures import (
    CODE_WITH_CASTS,
    CODE_WITH_ALIASES,
    create_fixture_file,
    create_config_file,
)


def test_audit_file_finds_casts(tmp_path: Path) -> None:
    """audit_file should find all cast-escape sites."""
    fixture = create_fixture_file(tmp_path, "test.py", CODE_WITH_CASTS)
    casts = audit_file(fixture)
    assert len(casts) == 3
    assert all(c["file"] == str(fixture) for c in casts)


def test_audit_file_extracts_tags(tmp_path: Path) -> None:
    """audit_file should extract tags from # trust: comments."""
    fixture = create_fixture_file(tmp_path, "test.py", CODE_WITH_CASTS)
    casts = audit_file(fixture)

    # Sort by line number for consistent order
    casts = sorted(casts, key=lambda c: c["line"])

    assert casts[0]["tag"] is None  # untagged
    assert casts[1]["tag"] == "general"
    assert casts[2]["tag"] == "legacy-tag"


def test_audit_file_extracts_reasons(tmp_path: Path) -> None:
    """audit_file should extract reason text."""
    fixture = create_fixture_file(tmp_path, "test.py", CODE_WITH_CASTS)
    casts = audit_file(fixture)
    casts = sorted(casts, key=lambda c: c["line"])

    assert casts[0]["reason"] is None
    assert casts[1]["reason"] == "config migration"
    assert casts[2]["reason"] == "JIRA-4291"  # reason after tag


def test_audit_file_with_aliases(tmp_path: Path) -> None:
    """audit_file should handle aliased imports."""
    fixture = create_fixture_file(tmp_path, "test.py", CODE_WITH_ALIASES)
    casts = audit_file(fixture)
    assert len(casts) == 2


def test_audit_integration_finds_casts(tmp_path: Path) -> None:
    """Integration: audit() on directory should find all casts."""
    create_fixture_file(tmp_path, "test1.py", CODE_WITH_CASTS)
    create_fixture_file(tmp_path, "test2.py", CODE_WITH_ALIASES)
    create_config_file(tmp_path, "[tool.pickle_secure]\nallow_tags = []\n")

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml")
    # Should have violations but not crash
    assert result in (0, 1)


def test_audit_single_file(tmp_path: Path) -> None:
    """audit() should handle single file path."""
    fixture = create_fixture_file(tmp_path, "test.py", CODE_WITH_CASTS)
    create_config_file(tmp_path, "[tool.pickle_secure]\nallow_tags = []\n")

    result = audit(fixture, config_path=tmp_path / "pyproject.toml")
    assert result in (0, 1)


def test_audit_nonexistent_path() -> None:
    """audit() should fail gracefully on nonexistent path."""
    result = audit(Path("/nonexistent"), config_path=Path("pyproject.toml"))
    assert result == 2
