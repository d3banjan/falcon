"""Test fixtures for audit command."""

from pathlib import Path

# Fixture: three simple cast-escape sites
CODE_WITH_CASTS = """\
from typing import cast
import pickle

# Site 1: untagged
data1 = cast(dict, pickle.loads(b"data"))

# Site 2: with general tag
data2 = cast(dict, pickle.loads(b"data"))  # trust: general config migration

# Site 3: with legacy tag (denied in config)
data3 = cast(dict, pickle.loads(b"data"))  # trust: legacy-tag JIRA-4291
"""

# Fixture: aliased imports
CODE_WITH_ALIASES = """\
from typing import cast as c
import pickle as p

data = c(dict, p.loads(b"data"))  # trust: test-fixture

from pickle import loads as decode
data2 = c(dict, decode(b"data"))
"""

# Fixture: Unpickler pattern
CODE_WITH_UNPICKLER = """\
from typing import cast
import pickle

# Direct Unpickler
unpickler = pickle.Unpickler(fp)
data = cast(list, unpickler.load())  # trust: file-deserialization

# _pickle variant
import _pickle
data2 = cast(dict, _pickle.loads(b"x"))  # trust: internal-only reason text here
"""

# Fixture: mixed tags and no tags
CODE_MIXED_TAGS = """\
from typing import cast
import pickle

# Allowed tag
x1 = cast(dict, pickle.loads(b"1"))  # trust: general
x2 = cast(dict, pickle.loads(b"2"))  # trust: general
x3 = cast(dict, pickle.loads(b"3"))  # trust: general

# Denied tag
y1 = cast(dict, pickle.loads(b"4"))  # trust: legacy-migration
y2 = cast(dict, pickle.loads(b"5"))  # trust: legacy-migration

# Unknown tag
z1 = cast(dict, pickle.loads(b"6"))  # trust: custom-tag

# Untagged
w1 = cast(dict, pickle.loads(b"7"))
w2 = cast(dict, pickle.loads(b"8"))
"""

# Config that requires reason on legacy-migration
CONFIG_WITH_REASON_REQUIRED = """\
[tool.falcon_secure]
allow_tags = ["general", "test-fixture"]
deny_tags = ["legacy-migration"]
require_reason = ["legacy-migration"]
unknown_tag = "error"
"""

# Config with unknown_tag = "warn"
CONFIG_WITH_UNKNOWN_WARN = """\
[tool.falcon_secure]
allow_tags = ["general", "test-fixture"]
unknown_tag = "warn"
"""


def create_fixture_file(tmp_path: Path, name: str, content: str) -> Path:
    """Create a fixture .py file in tmp_path."""
    file_path = tmp_path / name
    file_path.write_text(content)
    return file_path


def create_config_file(tmp_path: Path, content: str) -> Path:
    """Create a pyproject.toml with falcon_secure config."""
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text(content)
    return config_path
