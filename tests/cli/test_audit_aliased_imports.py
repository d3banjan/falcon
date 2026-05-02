"""Test falcon-secure audit — aliased imports."""

from pathlib import Path


from falcon_secure.cli.audit_cmd import audit_file
from tests.cli.fixtures import CODE_WITH_ALIASES, create_fixture_file


def test_audit_cast_alias(tmp_path: Path) -> None:
    """Should detect cast when aliased: from typing import cast as c."""
    fixture = create_fixture_file(tmp_path, "test.py", CODE_WITH_ALIASES)
    casts = audit_file(fixture)
    assert len(casts) >= 1


def test_audit_pickle_alias(tmp_path: Path) -> None:
    """Should detect pickle.loads when pickle aliased: import pickle as p."""
    code = """\
from typing import cast
import pickle as p

data = cast(dict, p.loads(b"x"))  # trust: test
"""
    fixture = create_fixture_file(tmp_path, "test.py", code)
    casts = audit_file(fixture)
    assert len(casts) == 1
    assert casts[0]["tag"] == "test"


def test_audit_from_import_loads(tmp_path: Path) -> None:
    """Should detect from pickle import loads."""
    code = """\
from typing import cast
from pickle import loads

data = cast(dict, loads(b"x"))  # trust: direct-import
"""
    fixture = create_fixture_file(tmp_path, "test.py", code)
    casts = audit_file(fixture)
    assert len(casts) == 1


def test_audit_underscore_pickle(tmp_path: Path) -> None:
    """Should detect _pickle.loads and Unpickler(...).load()."""
    code = """\
from typing import cast
import _pickle

data = cast(dict, _pickle.loads(b"x"))  # trust: internal

obj = cast(list, _pickle.Unpickler(fp).load())  # trust: internal
"""
    fixture = create_fixture_file(tmp_path, "test.py", code)
    casts = audit_file(fixture)
    assert len(casts) == 2


def test_audit_from_underscore_pickle(tmp_path: Path) -> None:
    """Should detect from _pickle import loads."""
    code = """\
from typing import cast
from _pickle import loads

data = cast(dict, loads(b"x"))  # trust: cpython
"""
    fixture = create_fixture_file(tmp_path, "test.py", code)
    casts = audit_file(fixture)
    assert len(casts) == 1
