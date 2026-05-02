"""Test falcon-secure audit — JSON output."""

import json
from pathlib import Path


from falcon_secure.cli.audit_cmd import audit
from tests.cli.fixtures import CODE_WITH_CASTS, create_fixture_file, create_config_file


def test_audit_json_output(tmp_path: Path, capsys) -> None:
    """audit --json should produce valid JSON."""
    create_fixture_file(tmp_path, "test.py", CODE_WITH_CASTS)
    create_config_file(
        tmp_path,
        """\
[tool.falcon_secure]
allow_tags = ["general", "test-fixture"]
unknown_tag = "error"
""",
    )

    audit(tmp_path, config_path=tmp_path / "pyproject.toml", json_output=True)
    captured = capsys.readouterr()
    output = captured.out

    # Should be valid JSON
    data = json.loads(output)
    assert "total_casts" in data
    assert "violations" in data
    assert isinstance(data["violations"], list)


def test_audit_json_violations(tmp_path: Path, capsys) -> None:
    """JSON output should include violation details."""
    code = """\
from typing import cast
import pickle

data = cast(dict, pickle.loads(b"x"))  # trust: denied-tag
"""
    create_fixture_file(tmp_path, "test.py", code)
    create_config_file(
        tmp_path,
        """\
[tool.falcon_secure]
allow_tags = ["general"]
deny_tags = ["denied-tag"]
unknown_tag = "error"
""",
    )

    audit(tmp_path, config_path=tmp_path / "pyproject.toml", json_output=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    # Should have 1 violation
    assert len(data["violations"]) >= 1
    violation = data["violations"][0]
    assert violation["type"] == "denied_tag"
    assert "file" in violation
    assert "line" in violation
    assert "message" in violation


def test_audit_json_by_tag(tmp_path: Path, capsys) -> None:
    """JSON should include by_tag grouping."""
    create_fixture_file(tmp_path, "test.py", CODE_WITH_CASTS)
    create_config_file(
        tmp_path,
        """\
[tool.falcon_secure]
allow_tags = ["general", "test-fixture"]
unknown_tag = "allow"
""",
    )

    audit(tmp_path, config_path=tmp_path / "pyproject.toml", json_output=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert "by_tag" in data
    assert isinstance(data["by_tag"], dict)


def test_audit_json_lists_trust_promotions(tmp_path: Path, capsys) -> None:
    """JSON output lists trusted provenance promotion sites."""
    code = """\
from pathlib import Path
from falcon_secure.trust import trusted_bytes, trusted_path, verify_path_sha256

payload = trusted_bytes(b"x", reason="fixture")
path = trusted_path(Path("model.pkl"), reason="fixture")
verified = verify_path_sha256(Path("model.pkl"), "0" * 64)
"""
    create_fixture_file(tmp_path, "test.py", code)
    create_config_file(tmp_path, "[tool.falcon_secure]\nunknown_tag = \"allow\"\n")

    audit(tmp_path, config_path=tmp_path / "pyproject.toml", json_output=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    promotions = data["trust_promotions"]
    assert len(promotions) == 3
    assert {item["category"] for item in promotions} == {"trusted-bytes", "trusted-path"}
