"""Infra test: PEP 561 stub package shadows typeshed in fresh venv.

Creates a fresh venv, pip installs pickle-stubs-secure in editable mode,
installs mypy, then runs mypy on a fixture importing pickle.loads and
asserts Unsafe[Any] appears in the error output.

This proves the stub package actually overrides stdlib stubs when installed.

Note: Uses mypy_path mechanism (pyproject.toml sets stubs/ as mypy_path).
The venv test verifies the full installation path.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
import venv
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent.parent

FIXTURE_CODE = textwrap.dedent("""\
    import pickle

    data = b""
    result = pickle.loads(data)
    x: dict = result
""")

MYPY_CONFIG = textwrap.dedent("""\
    [tool.mypy]
    python_version = "3.11"
    strict = true
    mypy_path = ["stubs"]
""")


@pytest.mark.slow
def test_pep561_stub_overrides_typeshed(tmp_path: Path) -> None:
    """Fresh venv + pip install → mypy sees Unsafe[Any] on pickle.loads."""
    venv_dir = tmp_path / "test_venv"
    venv.create(str(venv_dir), with_pip=True)

    if sys.platform == "win32":
        python = venv_dir / "Scripts" / "python.exe"
        pip = venv_dir / "Scripts" / "pip.exe"
    else:
        python = venv_dir / "bin" / "python"
        pip = venv_dir / "bin" / "pip"

    # Install the package in editable mode
    result = subprocess.run(
        [str(pip), "install", "-e", str(PROJECT_ROOT), "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"pip install failed:\n{result.stderr}"

    # Install mypy
    result = subprocess.run(
        [str(pip), "install", "mypy==1.13.*", "--quiet"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"mypy install failed:\n{result.stderr}"

    # Write fixture
    fixture = tmp_path / "test_fixture.py"
    fixture.write_text(FIXTURE_CODE)

    # Write a minimal pyproject.toml so mypy finds stubs/
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(MYPY_CONFIG)

    # Run mypy on fixture from the project root (so stubs/ is found)
    result = subprocess.run(
        [str(python), "-m", "mypy", "--strict", str(fixture)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
        timeout=60,
    )

    output = result.stdout + result.stderr
    assert result.returncode != 0, (
        f"Expected mypy to fail on pickle.loads usage but got exit 0:\n{output}"
    )
    assert "Unsafe[Any]" in output, (
        f"Expected 'Unsafe[Any]' in mypy output but got:\n{output}"
    )
