"""Fixture: provenance-gated loaders require trusted inputs and return Unsafe[Any]."""

from pathlib import Path
from typing import Any, cast

from pickle_stubs_secure.loaders import joblib_load, pickle_loads
from pickle_stubs_secure.trust import trusted_bytes, trusted_path

raw_path = Path("model.joblib")
raw_payload = b"\x80\x04."

raw_path_result = joblib_load(raw_path)
trusted_model_path = trusted_path(raw_path, reason="checked repository fixture")
unsafe_model = joblib_load(trusted_model_path)
model: dict[str, Any] = unsafe_model

raw_payload_result = pickle_loads(raw_payload)
trusted_payload = trusted_bytes(raw_payload, reason="checked repository fixture")
unsafe_payload = pickle_loads(trusted_payload)
payload: dict[str, Any] = unsafe_payload

reviewed_model = cast(dict[str, Any], unsafe_model)
