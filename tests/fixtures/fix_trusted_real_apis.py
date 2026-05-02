"""Fixture: real loaders require trusted provenance and still return Unsafe[Any]."""

from io import BytesIO
from pathlib import Path
from typing import Any, BinaryIO

import cloudpickle
import dill
import joblib
import pandas as pd
import pickle
import torch
from langchain.vectorstores.faiss import FAISS as LegacyFAISS
from langchain_community.vectorstores.faiss import FAISS
from llama_index.core.workflow import JsonPickleSerializer
from pandas.io import pickle as pandas_io_pickle
from pipecat.serializers.livekit import LivekitFrameSerializer
from falcon_secure.trust import trusted_binary_io, trusted_bytes, trusted_path

raw_path = Path("model.pkl")
raw_payload = b"\x80\x04."
raw_stream: BinaryIO = BytesIO(raw_payload)
embeddings: object = object()

raw_pickle_result = pickle.loads(raw_payload)
trusted_payload = trusted_bytes(raw_payload, reason="fixture digest checked")
unsafe_pickle = pickle.loads(trusted_payload)
pickle_value: dict[str, Any] = unsafe_pickle

raw_cloudpickle_loads_result = cloudpickle.loads(raw_payload)
unsafe_cloudpickle_loads = cloudpickle.loads(trusted_payload)
cloudpickle_loads_value: dict[str, Any] = unsafe_cloudpickle_loads

raw_cloudpickle_load_result = cloudpickle.load(raw_stream)
trusted_stream = trusted_binary_io(raw_stream, reason="fixture digest checked")
unsafe_cloudpickle_load = cloudpickle.load(trusted_stream)
cloudpickle_load_value: dict[str, Any] = unsafe_cloudpickle_load

raw_dill_loads_result = dill.loads(raw_payload)
unsafe_dill_loads = dill.loads(trusted_payload)
dill_loads_value: dict[str, Any] = unsafe_dill_loads

raw_dill_load_result = dill.load(raw_stream)
unsafe_dill_load = dill.load(trusted_stream)
dill_load_value: dict[str, Any] = unsafe_dill_load

raw_joblib_result = joblib.load(raw_path)
trusted_model_path = trusted_path(raw_path, reason="fixture digest checked")
unsafe_joblib = joblib.load(trusted_model_path)
joblib_value: dict[str, Any] = unsafe_joblib

raw_pandas_result = pd.read_pickle(raw_path)
unsafe_pandas = pd.read_pickle(trusted_model_path)
pandas_value: dict[str, Any] = unsafe_pandas

raw_pandas_io_result = pandas_io_pickle.read_pickle(raw_path)
unsafe_pandas_io = pandas_io_pickle.read_pickle(trusted_model_path)
pandas_io_value: dict[str, Any] = unsafe_pandas_io

raw_torch_result = torch.load(raw_path)
unsafe_torch = torch.load(trusted_model_path)
torch_value: dict[str, Any] = unsafe_torch

raw_faiss_bytes_result = FAISS.deserialize_from_bytes(raw_payload, embeddings)
unsafe_faiss_bytes = FAISS.deserialize_from_bytes(trusted_payload, embeddings)
faiss_bytes_value: dict[str, Any] = unsafe_faiss_bytes

raw_faiss_path_result = FAISS.load_local(raw_path, embeddings)
raw_faiss_str_path_result = FAISS.load_local("index", embeddings)
unsafe_faiss_path = FAISS.load_local(trusted_model_path, embeddings)
faiss_path_value: dict[str, Any] = unsafe_faiss_path

raw_legacy_faiss_bytes_result = LegacyFAISS.deserialize_from_bytes(raw_payload, embeddings)
unsafe_legacy_faiss_bytes = LegacyFAISS.deserialize_from_bytes(trusted_payload, embeddings)
legacy_faiss_bytes_value: dict[str, Any] = unsafe_legacy_faiss_bytes

raw_legacy_faiss_path_result = LegacyFAISS.load_local(raw_path, embeddings)
raw_legacy_faiss_str_path_result = LegacyFAISS.load_local("index", embeddings)
unsafe_legacy_faiss_path = LegacyFAISS.load_local(trusted_model_path, embeddings)
legacy_faiss_path_value: dict[str, Any] = unsafe_legacy_faiss_path

serializer = JsonPickleSerializer()
unsafe_llama_deserialize = serializer.deserialize("payload")
llama_deserialize_value: dict[str, Any] = unsafe_llama_deserialize

async def pipecat_deserialize_checks() -> None:
    _raw_pipecat_result = await LivekitFrameSerializer().deserialize(raw_payload)
    unsafe_pipecat = await LivekitFrameSerializer().deserialize(trusted_payload)
    _pipecat_value: dict[str, Any] = unsafe_pipecat
