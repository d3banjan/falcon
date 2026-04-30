"""Fixture: CVE-backed third-party wrappers that delegate to pickle-like deserialization."""

from typing import Any, cast

import numpy as np
import pyfory
import torch
from langchain_community.vectorstores.faiss import FAISS
from pipecat.serializers.livekit import LivekitFrameSerializer
from torch_musa.utils.compare_tool import compare_for_single_op


payload = b"..."

numpy_model: dict[str, Any] = np.load("model.npy", allow_pickle=True)
faiss_index: dict[str, Any] = FAISS.deserialize_from_bytes(payload)
fory_value: dict[str, Any] = pyfory.loads(payload)
torch_value: dict[str, Any] = torch.load("checkpoint.pt")
frame: dict[str, Any] = LivekitFrameSerializer().deserialize(payload)
comparison: dict[str, Any] = compare_for_single_op("payload.pkl")

reviewed = cast(dict[str, Any], FAISS.deserialize_from_bytes(payload))  # trust: cve-regression fixture

