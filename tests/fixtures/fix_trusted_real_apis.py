"""Fixture: real loaders require trusted provenance and still return Unsafe[Any]."""

from pathlib import Path
from typing import Any

import joblib
import pickle
import torch
from pickle_stubs_secure.trust import trusted_bytes, trusted_path

raw_path = Path("model.pkl")
raw_payload = b"\x80\x04."

raw_pickle_result = pickle.loads(raw_payload)
trusted_payload = trusted_bytes(raw_payload, reason="fixture digest checked")
unsafe_pickle = pickle.loads(trusted_payload)
pickle_value: dict[str, Any] = unsafe_pickle

raw_joblib_result = joblib.load(raw_path)
trusted_model_path = trusted_path(raw_path, reason="fixture digest checked")
unsafe_joblib = joblib.load(trusted_model_path)
joblib_value: dict[str, Any] = unsafe_joblib

raw_torch_result = torch.load(raw_path)
unsafe_torch = torch.load(trusted_model_path)
torch_value: dict[str, Any] = unsafe_torch
