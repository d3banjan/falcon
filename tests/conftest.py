"""Pytest configuration for project."""
import os
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent

MYPY_BIN = os.environ.get("MYPY_BIN", shutil.which("mypy") or "mypy")
PYRIGHT_BIN = os.environ.get("PYRIGHT_BIN", shutil.which("pyright") or "pyright")


def mypy_check(fixture: Path) -> tuple[int, str]:
    """Run mypy --strict on a fixture file.

    Returns exit code and combined stdout/stderr.
    """
    result = subprocess.run(
        [MYPY_BIN, "--strict", str(fixture)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode, result.stdout + result.stderr


def pyright_check(fixture: Path) -> tuple[int, str]:
    """Run pyright on a fixture file.

    Returns exit code and combined stdout/stderr.
    """
    result = subprocess.run(
        [PYRIGHT_BIN, "--warnings", str(fixture)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode, result.stdout + result.stderr


# Add stub directory to Python path for imports
stubs_path = PROJECT_ROOT / "stubs"
sys.path.insert(0, str(stubs_path))
