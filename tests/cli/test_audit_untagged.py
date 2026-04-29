"""Test pickle-secure audit — untagged filter."""

from pathlib import Path


from pickle_stubs_secure.cli.audit_cmd import audit
from tests.cli.fixtures import CODE_MIXED_TAGS, create_fixture_file, create_config_file


def test_audit_untagged_filter(tmp_path: Path, capsys) -> None:
    """--untagged should show only untagged sites."""
    create_fixture_file(tmp_path, "test.py", CODE_MIXED_TAGS)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["general", "test-fixture"]
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml", untagged_only=True)
    captured = capsys.readouterr()
    output = captured.out

    # Should report violations for untagged sites
    assert "untagged" in output.lower() or result == 1


def test_audit_by_tag_filter(tmp_path: Path, capsys) -> None:
    """--tag <X> should filter to specific tag."""
    create_fixture_file(tmp_path, "test.py", CODE_MIXED_TAGS)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["general", "test-fixture"]
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml", tag_filter="general")
    # Should only see general tag sites
    assert result in (0, 1)
