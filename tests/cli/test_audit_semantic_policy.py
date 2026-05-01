"""Test pickle-secure audit semantic-policy findings."""

import json
from pathlib import Path

from pickle_stubs_secure.cli.audit_cmd import audit, audit_semantic_policy_file
from tests.cli.fixtures import create_config_file, create_fixture_file


def test_audit_semantic_policy_detects_class_unsafe_config(tmp_path: Path) -> None:
    code = """\
class LoaderConfig:
    safe = False
    remote_exec = True
"""
    fixture = create_fixture_file(tmp_path, "unsafe_config.py", code)

    findings = audit_semantic_policy_file(fixture)

    assert [finding["rule"] for finding in findings] == [
        "class-safe-false",
        "class-remote-exec-true",
    ]
    assert all(finding["category"] == "unsafe-config" for finding in findings)
    assert all(finding["catchability"] == "checker-rule-needed" for finding in findings)


def test_audit_semantic_policy_detects_super_init_unsafe_config(
    tmp_path: Path,
) -> None:
    code = """\
class UnsafeLoader(BaseLoader):
    def __init__(self) -> None:
        super().__init__(safe=False)
"""
    fixture = create_fixture_file(tmp_path, "super_init.py", code)

    findings = audit_semantic_policy_file(fixture)

    assert len(findings) == 1
    assert findings[0]["rule"] == "super-init-unsafe-config"
    assert "safe=False" in findings[0]["message"]


def test_audit_semantic_policy_detects_direct_constructor_config(
    tmp_path: Path,
) -> None:
    code = """\
loader = DangerousLoader(safe=False)
client = package.RemoteClient(remote_exec=True)
"""
    fixture = create_fixture_file(tmp_path, "constructor_config.py", code)

    findings = audit_semantic_policy_file(fixture)

    assert [finding["rule"] for finding in findings] == [
        "constructor-unsafe-config",
        "constructor-unsafe-config",
    ]
    assert "safe=False" in findings[0]["message"]
    assert "remote_exec=True" in findings[1]["message"]


def test_audit_semantic_policy_ignores_safe_literal_config(tmp_path: Path) -> None:
    code = """\
class LoaderConfig:
    safe = True
    remote_exec = False

safe = False
allow_remote = remote_exec(True)
loader = build_loader(safe=False)

class MethodLocal:
    def configure(self) -> None:
        safe = False
        remote_exec = True
"""
    fixture = create_fixture_file(tmp_path, "safe_config.py", code)

    assert audit_semantic_policy_file(fixture) == []


def test_audit_json_includes_semantic_policy_findings(
    tmp_path: Path,
    capsys,
) -> None:
    code = """\
class LoaderConfig:
    safe = False
"""
    create_fixture_file(tmp_path, "unsafe_config.py", code)
    create_config_file(tmp_path, "[tool.pickle_secure]\nallow_tags = []\n")

    result = audit(tmp_path, config_path=tmp_path / "pyproject.toml", json_output=True)
    captured = capsys.readouterr()
    data = json.loads(captured.out)

    assert result == 1
    assert data["total_casts"] == 0
    assert data["semantic_findings"][0]["category"] == "unsafe-config"
    assert data["violations"][0]["catchability"] == "checker-rule-needed"
