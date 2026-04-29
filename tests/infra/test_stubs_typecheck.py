"""Infra test: the stubs themselves are clean under mypy --strict.

Verifies that running mypy --strict on a fixture that imports pickle
(using our stubs via mypy_path) exits 0 when there are no deserialization calls.

This validates:
  1. Our stub files have no internal type errors.
  2. `from pickle import dump, dumps, Pickler` (safe APIs) passes strict.
  3. The Unsafe type is well-formed (Generic, final, no internal errors).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent


def mypy_run(code: str, tmp_path: Path) -> tuple[int, str]:
    """Write code to a tmp file and run mypy --strict on it."""
    fixture = tmp_path / "stub_check.py"
    fixture.write_text(code)
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--strict", str(fixture)],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode, result.stdout + result.stderr


def test_safe_apis_pass_strict(tmp_path: Path) -> None:
    """pickle.dump/dumps/Pickler (serialize-only) pass strict with no errors."""
    code = textwrap.dedent("""\
        import io
        import pickle

        def serialize_safe(obj: object) -> bytes:
            return pickle.dumps(obj)

        def serialize_to_file(obj: object, path: str) -> None:
            with open(path, "wb") as f:
                pickle.dump(obj, f)
    """)
    rc, output = mypy_run(code, tmp_path)
    assert rc == 0, f"Expected mypy to pass on safe APIs but got errors:\n{output}"


def test_unsafe_type_is_well_formed(tmp_path: Path) -> None:
    """Unsafe[T] stub is valid: final, generic, has unwrap."""
    code = textwrap.dedent("""\
        from _unsafe import Unsafe
        from typing import Any

        def consume(u: Unsafe[Any]) -> None:
            val: Any = u.unwrap()
            _ = val
    """)
    rc, output = mypy_run(code, tmp_path)
    assert rc == 0, f"Unsafe type has internal errors:\n{output}"


def test_loads_returns_unsafe(tmp_path: Path) -> None:
    """pickle.loads return type is Unsafe[Any] — cannot assign to dict without error."""
    code = textwrap.dedent("""\
        import pickle
        from _unsafe import Unsafe
        from typing import Any

        def deserialize(data: bytes) -> Unsafe[Any]:
            return pickle.loads(data)
    """)
    rc, output = mypy_run(code, tmp_path)
    assert rc == 0, f"Stub return type mismatch:\n{output}"


def test_load_returns_unsafe(tmp_path: Path) -> None:
    """pickle.load return type is Unsafe[Any]."""
    code = textwrap.dedent("""\
        import io
        import pickle
        from _unsafe import Unsafe
        from typing import Any

        def deserialize_file(f: io.BytesIO) -> Unsafe[Any]:
            return pickle.load(f)
    """)
    rc, output = mypy_run(code, tmp_path)
    assert rc == 0, f"pickle.load return type mismatch:\n{output}"


def test_unpickler_load_returns_unsafe(tmp_path: Path) -> None:
    """pickle.Unpickler.load() return type is Unsafe[Any]."""
    code = textwrap.dedent("""\
        import io
        import pickle
        from _unsafe import Unsafe
        from typing import Any

        def deserialize_unpickler(data: bytes) -> Unsafe[Any]:
            u = pickle.Unpickler(io.BytesIO(data))
            return u.load()
    """)
    rc, output = mypy_run(code, tmp_path)
    assert rc == 0, f"Unpickler.load return type mismatch:\n{output}"
