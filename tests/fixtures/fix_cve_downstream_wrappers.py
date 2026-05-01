"""Fixture: CVE-backed third-party wrappers that delegate to pickle-like deserialization."""

from typing import Any, cast

import cloudpickle
import jsonpickle
import numpy as np
import pyfory
import socketio
import stepfun_ai
import torch
from kedro.io import ShelveStore
from langchain.vectorstores.faiss import FAISS as LegacyFAISS
from langchain_community.vectorstores.faiss import FAISS
from llama_index.core import JsonPickleSerializer
from pipecat.serializers.livekit import LivekitFrameSerializer
from smolagents import RemotePythonExecutor
from torch_musa.utils.compare_tool import compare_for_single_op
from torch_musa.utils.compare_tool import nan_inf_track_for_single_op


payload = b"..."

cloudpickle_value: dict[str, Any] = cloudpickle.loads(payload)
jsonpickle_value: dict[str, Any] = jsonpickle.decode("{}")
numpy_model: dict[str, Any] = np.load("model.npy", allow_pickle=True)
faiss_index: dict[str, Any] = FAISS.deserialize_from_bytes(payload)
legacy_faiss_index: dict[str, Any] = LegacyFAISS.deserialize_from_bytes(payload)
legacy_faiss_local: dict[str, Any] = LegacyFAISS.load_local("index")
kedro_session: dict[str, Any] = ShelveStore()["session"]
llama_value: dict[str, Any] = JsonPickleSerializer().deserialize(payload)
fory_value: dict[str, Any] = pyfory.loads(payload)
socketio_value: dict[str, Any] = socketio.RedisManager()._handle_emit(payload)
smolagents_value: dict[str, Any] = RemotePythonExecutor().deserialize(payload)
stepfun_value: dict[str, Any] = stepfun_ai.call_remote_server(payload)
torch_value: dict[str, Any] = torch.load("checkpoint.pt")
frame: dict[str, Any] = LivekitFrameSerializer().deserialize(payload)
comparison: dict[str, Any] = compare_for_single_op("payload.pkl")
comparison_nan: dict[str, Any] = nan_inf_track_for_single_op("payload.pkl")

reviewed = cast(dict[str, Any], FAISS.deserialize_from_bytes(payload))  # trust: cve-regression fixture
