"""Strict-profile end-to-end integration tests.

Verify that --profile=strict writes correct mypy config knobs,
and that running mypy with those knobs catches soundness holes
that basic profile does not catch.

Each test is self-contained: write config -> create fixture -> run mypy -> assert.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

STUBS_DIR = Path(__file__).parent.parent.parent / "stubs"

STRICT_MYPY_KNOBS = """\
disallow_any_explicit = true
disallow_any_expr = true
disallow_any_decorated = true
disallow_any_generics = true
disallow_subclassing_any = true
warn_return_any = true
warn_unused_ignores = true
no_implicit_reexport = true
"""


def _write_strict_pyproject(tmp_path: Path) -> Path:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"""\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.mypy]
mypy_path = ["{STUBS_DIR}"]
{STRICT_MYPY_KNOBS}
""")
    return pyproject


def _write_basic_pyproject(tmp_path: Path) -> Path:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"""\
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.mypy]
mypy_path = ["{STUBS_DIR}"]
""")
    return pyproject


def _run_mypy(fixture: Path, cwd: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, "-m", "mypy", str(fixture)],
        capture_output=True,
        text=True,
        cwd=str(cwd),
    )
    return result.returncode, result.stdout + result.stderr


ANY_EXPLICIT_FIXTURE = """\
from typing import Any
import pickle

data = b""
x: Any = pickle.loads(data)
print(x)
"""

ANY_EXPR_FIXTURE = """\
import pickle

data = b""
fn = getattr(pickle, "loads")
print(fn)
"""

WARN_RETURN_ANY_FIXTURE = """\
from typing import Any
import pickle

def source() -> Any:
    return pickle.loads(b"")

def sink(data: bytes) -> str:
    return source()

print(sink(b""))
"""


class TestStrictProfileCatchesAnyLeaks:
    def test_disallow_any_explicit(self, tmp_path: Path) -> None:
        """x: Any = pickle.loads(...) — strict profile catches explicit Any annotation."""
        _write_strict_pyproject(tmp_path)
        fixture = tmp_path / "test_any_explicit.py"
        fixture.write_text(ANY_EXPLICIT_FIXTURE)
        rc, output = _run_mypy(fixture, tmp_path)
        assert rc != 0, f"Expected mypy to fail, got rc={rc}\n{output}"
        assert 'Explicit "Any" is not allowed' in output, (
            f"Expected disallow_any_explicit error, got:\n{output}"
        )

    def test_disallow_any_expr(self, tmp_path: Path) -> None:
        """getattr(pickle, 'loads') — strict profile catches expression of type Any."""
        _write_strict_pyproject(tmp_path)
        fixture = tmp_path / "test_any_expr.py"
        fixture.write_text(ANY_EXPR_FIXTURE)
        rc, output = _run_mypy(fixture, tmp_path)
        assert rc != 0, f"Expected mypy to fail, got rc={rc}\n{output}"
        assert '[misc]' in output, (
            f"Expected disallow_any_expr error (misc), got:\n{output}"
        )

    def test_warn_return_any(self, tmp_path: Path) -> None:
        """Function returning Any — strict profile warns on return_any."""
        _write_strict_pyproject(tmp_path)
        fixture = tmp_path / "test_warn_return_any.py"
        fixture.write_text(WARN_RETURN_ANY_FIXTURE)
        rc, output = _run_mypy(fixture, tmp_path)
        assert rc != 0, f"Expected mypy to fail, got rc={rc}\n{output}"
        assert 'warn_return_any' in output.lower() or '[no-any-return]' in output, (
            f"Expected warn_return_any error, got:\n{output}"
        )


class TestBasicProfileDoesNotCatchAnyLeaks:
    def test_any_explicit_not_caught(self, tmp_path: Path) -> None:
        """Basic profile does NOT catch x: Any = pickle.loads(...)."""
        _write_basic_pyproject(tmp_path)
        fixture = tmp_path / "test_any_explicit.py"
        fixture.write_text(ANY_EXPLICIT_FIXTURE)
        rc, output = _run_mypy(fixture, tmp_path)
        assert '[explicit-any]' not in output, (
            f"Basic profile raised explicit-any unexpectedly:\n{output}"
        )

    def test_any_expr_not_caught(self, tmp_path: Path) -> None:
        """Basic profile does NOT catch getattr expression of type Any."""
        _write_basic_pyproject(tmp_path)
        fixture = tmp_path / "test_any_expr.py"
        fixture.write_text(ANY_EXPR_FIXTURE)
        rc, output = _run_mypy(fixture, tmp_path)
        assert '[misc]' not in output, (
            f"Basic profile raised misc error unexpectedly:\n{output}"
        )

    def test_warn_return_any_not_caught(self, tmp_path: Path) -> None:
        """Basic profile does NOT warn on returning Any."""
        _write_basic_pyproject(tmp_path)
        fixture = tmp_path / "test_warn_return_any.py"
        fixture.write_text(WARN_RETURN_ANY_FIXTURE)
        rc, output = _run_mypy(fixture, tmp_path)
        assert '[no-any-return]' not in output, (
            f"Basic profile raised warn_return_any unexpectedly:\n{output}"
        )


class TestStrictProfileConfigIntegrity:
    def test_pyproject_written_correctly(self, tmp_path: Path) -> None:
        """Run pickle-secure init --profile=strict, verify all strict options present."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("""\
[tool.mypy]
strict = true
""")

        result = subprocess.run(
            [
                sys.executable, "-m", "pickle_stubs_secure.cli.main",
                "init", "--profile=strict",
                "--path", str(pyproject),
                "--checker", "mypy",
            ],
            capture_output=True,
            text=True,
            cwd=str(tmp_path),
        )
        assert result.returncode == 0, f"init failed: {result.stderr}"

        content = pyproject.read_text()

        # Strict mypy knobs
        assert "disallow_any_explicit = true" in content
        assert "disallow_any_expr = true" in content
        assert "disallow_any_decorated = true" in content
        assert "disallow_any_generics = true" in content
        assert "disallow_subclassing_any = true" in content
        assert "warn_return_any = true" in content
        assert "warn_unused_ignores = true" in content
        assert "no_implicit_reexport = true" in content

        # mypy_path was set
        assert "mypy_path" in content
        assert "stubs" in content

        # Ruff rules
        assert "PGH003" in content
        assert "S301" in content

        # pickle_secure config (allow_tags uses inline table syntax by tomlkit)
        assert "allow_tags" in content
