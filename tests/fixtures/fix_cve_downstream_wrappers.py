"""Fixture: CVE-backed third-party wrappers that delegate to pickle-like deserialization."""

from typing import Any, cast

import cloudpickle
import dill
import joblib
import jsonpickle
import marshal
import numpy as np
import pyfory
from skops.card import Card
import socketio
import stepfun_ai
import torch
import yaml
import pandas as pd
from embedchain.loaders.openapi import OpenAPILoader
from horovod.runner.common.util.codec import loads_base64
from invokeai.app.services.model_load.model_load_default import ModelLoadService
from invokeai.backend.model_manager.model_on_disk import ModelOnDisk
from kedro.io import ShelveStore
from langchain.vectorstores.faiss import FAISS as LegacyFAISS
from langchain_community.vectorstores.faiss import FAISS
from llama_index.core import JsonPickleSerializer
from pipecat.serializers.livekit import LivekitFrameSerializer
from smolagents import RemotePythonExecutor
from torch_musa.utils.compare_tool import compare_for_single_op
from torch_musa.utils.compare_tool import nan_inf_track_for_single_op
from pandas.io import pickle as pandas_io_pickle
from vllm.model_executor.model_loader.weight_utils import (
    multi_thread_pt_weights_iterator,
    pt_weights_iterator,
)


payload = b"..."

cloudpickle_value: dict[str, Any] = cloudpickle.loads(payload)
dill_value: dict[str, Any] = dill.loads(payload)
joblib_value: dict[str, Any] = joblib.load("model.joblib")
jsonpickle_value: dict[str, Any] = jsonpickle.decode("{}")
marshal_value: dict[str, Any] = marshal.loads(payload)
numpy_model: dict[str, Any] = np.load("model.npy", allow_pickle=True)
yaml_value: dict[str, Any] = yaml.load("!!python/object/apply:os.system ['id']")
pandas_model: dict[str, Any] = pd.read_pickle("frame.pkl")
pandas_io_model: dict[str, Any] = pandas_io_pickle.read_pickle("frame.pkl")
skops_model: dict[str, Any] = Card("model.skops").get_model()
embedchain_docs: list[dict[str, Any]] = OpenAPILoader().load_data("openapi.yaml")
horovod_value: dict[str, Any] = loads_base64("...")
invoke_state: dict[str, Any] = ModelOnDisk().load_state_dict("checkpoint.pt")
invoke_model: dict[str, Any] = ModelLoadService().load_model_from_path("checkpoint.pt")
faiss_index: dict[str, Any] = FAISS.deserialize_from_bytes(payload)
legacy_faiss_index: dict[str, Any] = LegacyFAISS.deserialize_from_bytes(payload)
legacy_faiss_local: dict[str, Any] = LegacyFAISS.load_local("index")
kedro_session: dict[str, Any] = ShelveStore()["session"]
kedro_get_session: dict[str, Any] = ShelveStore().get("session")
kedro_loaded_session: dict[str, Any] = ShelveStore().load("session")
llama_value: dict[str, Any] = JsonPickleSerializer().deserialize(payload)
llama_load_value: dict[str, Any] = JsonPickleSerializer().load(payload)
llama_loads_value: dict[str, Any] = JsonPickleSerializer().loads(payload)
fory_value: dict[str, Any] = pyfory.loads(payload)
socketio_value: dict[str, Any] = socketio.RedisManager()._handle_emit(payload)
socketio_callback: dict[str, Any] = socketio.RedisManager()._handle_callback(payload)
smolagents_value: dict[str, Any] = RemotePythonExecutor().deserialize(payload)
smolagents_loads_value: dict[str, Any] = RemotePythonExecutor().loads(payload)
stepfun_value: dict[str, Any] = stepfun_ai.call_remote_server(payload)
torch_value: dict[str, Any] = torch.load("checkpoint.pt")
frame: dict[str, Any] = LivekitFrameSerializer().deserialize(payload)
comparison: dict[str, Any] = compare_for_single_op("payload.pkl")
comparison_nan: dict[str, Any] = nan_inf_track_for_single_op("payload.pkl")
vllm_weight: dict[str, Any] = next(pt_weights_iterator("model"))
vllm_thread_weight: dict[str, Any] = next(multi_thread_pt_weights_iterator("model"))

reviewed = cast(dict[str, Any], FAISS.deserialize_from_bytes(payload))  # trust: cve-regression fixture
