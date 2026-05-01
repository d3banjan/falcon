"""Fixture: source-shaped direct pickle CVE flows without stable public wrappers."""

from typing import Any, BinaryIO
import gzip
import pickle


payload = b"..."


def ms_swift_load_model_meta(model_meta_file: BinaryIO) -> dict[str, Any]:
    """CVE-2025-50472: ModelFileSystemCache.load_model_meta."""
    metadata: dict[str, Any] = pickle.load(model_meta_file)
    return metadata


def tendenci_run_report(report_payload: bytes) -> dict[str, Any]:
    """CVE-2026-23946: Helpdesk run_report() report payload."""
    report: dict[str, Any] = pickle.loads(report_payload)
    return report


def pdfminer_load_cmap_data(cmap_pickle_gz: BinaryIO) -> dict[str, Any]:
    """CVE-2025-64512: CMapDB._load_data() reads compressed CMap data."""
    with gzip.GzipFile(fileobj=cmap_pickle_gz) as gzfile:
        cmap_data: dict[str, Any] = pickle.loads(gzfile.read())
    return cmap_data


def lerobot_send_policy_instructions(grpc_payload: bytes) -> dict[str, Any]:
    """CVE-2026-25874: gRPC policy instructions deserialize bytes."""
    instructions: dict[str, Any] = pickle.loads(grpc_payload)
    return instructions


def sglang_scheduler_client(zmq_payload: bytes) -> dict[str, Any]:
    """CVE-2026-3059: multimodal scheduler client ZMQ payload."""
    message: dict[str, Any] = pickle.loads(zmq_payload)
    return message


def sglang_encode_receiver(disaggregation_payload: bytes) -> dict[str, Any]:
    """CVE-2026-3060: encoder disaggregation payload."""
    request: dict[str, Any] = pickle.loads(disaggregation_payload)
    return request


def sglang_replay_request_dump(dump_file: BinaryIO) -> dict[str, Any]:
    """CVE-2026-3989: replay_request_dump.py pickle file load."""
    replay_request: dict[str, Any] = pickle.load(dump_file)
    return replay_request


def manga_image_translator_execute(request_body: bytes) -> dict[str, Any]:
    """CVE-2026-26215: execute endpoint request body."""
    job: dict[str, Any] = pickle.loads(request_body)
    return job


def ply_yacc_picklefile(picklefile: BinaryIO) -> dict[str, Any]:
    """CVE-2025-56005: yacc(..., picklefile=...) cache file."""
    grammar: dict[str, Any] = pickle.load(picklefile)
    return grammar

