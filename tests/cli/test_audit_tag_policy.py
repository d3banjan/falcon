"""Test pickle-secure audit — tag policy enforcement."""

from pathlib import Path


from pickle_stubs_secure.cli.audit_cmd import audit
from tests.cli.fixtures import (
    CODE_MIXED_TAGS,
    create_fixture_file,
    create_config_file,
)


def test_audit_tag_policy_allowed(tmp_path: Path) -> None:
    """Audit should allow whitelisted tags."""
    create_fixture_file(tmp_path, "test.py", CODE_MIXED_TAGS)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["general"]
deny_tags = []
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml")
    # Should report violations for unknown and denied tags
    assert result == 1


def test_audit_tag_policy_denied(tmp_path: Path) -> None:
    """Audit should reject denied tags."""
    create_fixture_file(tmp_path, "test.py", CODE_MIXED_TAGS)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["general"]
deny_tags = ["legacy-migration"]
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml")
    # Should report violations
    assert result == 1


def test_audit_tag_policy_unknown(tmp_path: Path) -> None:
    """Audit should flag unknown tags when unknown_tag='error'."""
    create_fixture_file(tmp_path, "test.py", CODE_MIXED_TAGS)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["general"]
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml")
    assert result == 1


def test_audit_require_reason(tmp_path: Path) -> None:
    """Audit should enforce require_reason on tags."""
    code = """\
from typing import cast
import pickle

# Has reason
x1 = cast(dict, pickle.loads(b"1"))  # trust: legacy-migration Reason: old code

# Missing reason
x2 = cast(dict, pickle.loads(b"2"))  # trust: legacy-migration
"""
    create_fixture_file(tmp_path, "test.py", code)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["legacy-migration"]
require_reason = ["legacy-migration"]
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml")
    # Should have violations on line with missing reason
    assert result == 1


def test_audit_untagged_violation(tmp_path: Path) -> None:
    """Untagged sites should appear as violations when unknown_tag='error'."""
    code = """\
from typing import cast
import pickle

data = cast(dict, pickle.loads(b"x"))
"""
    create_fixture_file(tmp_path, "test.py", code)
    create_config_file(
        tmp_path,
        """\
[tool.pickle_secure]
allow_tags = ["general"]
unknown_tag = "error"
""",
    )

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml")
    # Untagged site with unknown_tag='error' is a violation
    assert result == 1
