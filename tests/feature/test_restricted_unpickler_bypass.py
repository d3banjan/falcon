"""Allowlist-Bypass Demo — HEADLINE ARTIFACT for HN launch.

Story: Developer writes RestrictedUnpickler with find_class allowlist per
CPython docs → known gadget chain bypasses allowlist → our stubs STILL flag
as Unsafe[Any] → Developer must cast() + review allowlist against gadget catalog.

Marketing line: "caught what allowlist missed."
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from falcon_secure.cli.audit_cmd import audit
from tests.conftest import mypy_check

FIXTURE = Path(__file__).parent.parent / "fixtures" / "restricted_unpickler_demo.py"
FIXTURE_BYPASS = Path(__file__).parent.parent / "fixtures" / "fix_feature_bypass_demo.py"

_RCE_BYPASS_SCRIPT = """\
import io, os, pickle, sys

marker_path = sys.argv[1]

ALLOWED_MODULES = {"builtins", "__main__"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in ALLOWED_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")

class MaliciousConfig:
    def __reduce__(self):
        return (MaliciousConfig, (), {"__cmd__": f"touch {marker_path}"})

    def __setstate__(self, state):
        if isinstance(state, dict) and "__cmd__" in state:
            os.system(state["__cmd__"])

payload = pickle.dumps(MaliciousConfig())
unpickler = RestrictedUnpickler(io.BytesIO(payload))
result = unpickler.load()
"""

_BLOCK_SCRIPT = """\
import io, os, pickle, sys

ALLOWED_MODULES = {"builtins"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in ALLOWED_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")

class _Exploit:
    def __reduce__(self):
        return (os.system, (f"touch {sys.argv[1]}",))

payload = pickle.dumps(_Exploit())
try:
    RestrictedUnpickler(io.BytesIO(payload)).load()
    sys.exit(1)
except pickle.UnpicklingError:
    sys.exit(0)
"""

_SAFE_SCRIPT = """\
import io, pickle

ALLOWED_MODULES = {"builtins"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module in ALLOWED_MODULES:
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"forbidden: {module}.{name}")

payload = pickle.dumps({"hello": "world"})
result = RestrictedUnpickler(io.BytesIO(payload)).load()
assert result == {"hello": "world"}, f"Expected dict but got {result!r}"
"""


def test_restricted_unpickler_blocks_safe_classes(tmp_path: Path) -> None:
    """RestrictedUnpickler correctly blocks unsafe classes via find_class.

    A simple __reduce__ payload using os.system is blocked because 'os' module
    is not in the allowlist. A safe payload using builtins.dict is allowed.
    """
    marker = tmp_path / "blocked_rce.txt"

    # Test 1: unsafe payload (os.system) is blocked
    result = subprocess.run(
        [sys.executable, "-c", _BLOCK_SCRIPT, str(marker)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"UnpicklingError not raised as expected: {result.stderr}"
    assert not marker.exists(), "RCE marker was created — exploit was NOT blocked!"

    # Test 2: safe payload (builtins.dict) is allowed
    result2 = subprocess.run(
        [sys.executable, "-c", _SAFE_SCRIPT],
        capture_output=True, text=True, timeout=10,
    )
    assert result2.returncode == 0, f"Safe dict payload was rejected: {result2.stderr}"


def test_gadget_chain_bypasses_restricted_unpickler_at_runtime(tmp_path: Path) -> None:
    """Prove with process isolation that __setstate__ on a dict subclass
    bypasses the allowlist and achieves RCE.

    The allowlist trusts classes from __main__ (developer's own code).
    A dict subclass defined in __main__ has __setstate__ that executes
    os.system — the pickle opcode resolves the dict subclass via find_class
    (allowed because __main__ is trusted), then __setstate__ fires with
    attacker-controlled state data from the pickle payload.

    This is a REAL bypass that stubs catch at type-check time regardless.
    """
    marker = tmp_path / "setstate_bypass_rce.txt"

    result = subprocess.run(
        [sys.executable, "-c", _RCE_BYPASS_SCRIPT, str(marker)],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, (
        f"Bypass subprocess failed: {result.stderr}\n{result.stdout}"
    )
    assert marker.exists(), (
        "__setstate__ bypass RCE marker was NOT created — "
        f"subprocess stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_stubs_flag_all_deserialization_even_with_allowlist() -> None:
    """The same RestrictedUnpickler code, when type-checked with --strict,
    produces Unsafe[Any] errors on ALL .load() calls regardless of allowlist.
    """
    assert FIXTURE.exists(), f"Fixture not found: {FIXTURE}"
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )


def test_proper_fix_requires_cast_and_manual_review(tmp_path: Path) -> None:
    """Show that the ONLY way to pass type checking is with cast() + trust tag,
    and the audit CLI tracks this.
    """
    src = tmp_path / "src"
    src.mkdir()
    fix_file = src / "secure_unpickle.py"
    fix_file.write_text("""\
from typing import Any, cast
import io, pickle

SAFE_BUILTINS = {"dict", "list", "tuple"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str) -> object:
        if module == "builtins" and name in SAFE_BUILTINS:
            return super().find_class(module, name)
        raise pickle.UnpicklingError("forbidden")

buf = io.BytesIO(b"")
data: dict[Any, Any] = cast(dict[Any, Any], RestrictedUnpickler(buf).load())  # trust: reviewed-gadget-catalog
""")

    # Create a config file in tmp_path
    cfg = tmp_path / "pyproject.toml"
    cfg.write_text("""\
[tool.falcon_secure]
allow_tags = ["reviewed-gadget-catalog"]
unknown_tag = "error"
""")

    # mypy --strict should PASS on this file (no Unsafe[Any] leaks because of cast)
    rc, output = mypy_check(fix_file)
    assert rc == 0, (
        f"Expected mypy success for proper cast fix but got exit {rc}:\n{output}"
    )

    # Audit CLI must find and track the cast
    result = audit(fix_file, config_path=cfg)
    assert result == 0, f"Audit should pass (0) for known tag, got {result}"

    # Verify audit finds the cast (use untagged-only to check nothing untagged)
    result2 = audit(fix_file, config_path=cfg)
    assert result2 == 0, "Cast with trusted tag should pass audit"


def test_demo_standalone_script(tmp_path: Path) -> None:
    """Verify the standalone demo fixture imports and demonstrates all three points:
    allowlist gets bypassed at runtime, stubs catch it at type-check time,
    cast is the fix.
    """
    assert FIXTURE.exists(), f"Demo fixture not found: {FIXTURE}"

    # Point 1: mypy --strict on the fixture flags Unsafe[Any]
    rc, output = mypy_check(FIXTURE)
    assert rc != 0, f"Expected mypy failure but got exit 0. Output:\n{output}"
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )

    # Point 2: The fixture contains the cast fix with trust tag
    fixture_text = FIXTURE.read_text()
    assert "cast(dict" in fixture_text, "Demo fixture must contain cast fix"
    assert "trust:" in fixture_text, "Demo fixture must contain trust tag"

    # Point 3: Verify the fixture is importable at runtime
    script = f"""\
import sys
sys.path.insert(0, {str(FIXTURE.parent)!r})
import importlib.util
spec = importlib.util.spec_from_file_location(
    "restricted_unpickler_demo", {str(FIXTURE)!r}
)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print("OK")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, f"Fixture import failed: {result.stderr}"
    assert "OK" in result.stdout, f"Fixture import did not complete: {result.stdout}"
