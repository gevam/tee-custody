"""T-04 criteria 1-2: the frozen INC-2 `teecustody` API (INC-2-API §4, API-TL §2/§4) as transcribed.

Signatures are compared by `inspect.Signature` equality (names, order, kinds, defaults, annotations,
return annotation), exactly as INC-1's `test_api_surface.py` does. Stub bodies are never called here
(D-038): these tests pin shape only and stay green when the owning tasks implement the bodies.
"""

from __future__ import annotations

import dataclasses
import importlib
import inspect
import json
import os
import re
import subprocess
import sys
import threading
import time
import typing
from collections.abc import Callable, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Literal

import pytest

from teecustody.attest import AttestationToken, Launcher, RefreshOutcome
from teecustody.attest.claims import IMAGE_DIGEST_PATTERN, own_image_digest
from teecustody.audit import (
    AUDIT_ID_PATTERN,
    MAX_COUNT,
    AggregateOutcome,
    AppendResult,
    AuditClass,
    AuditEmitter,
    AuditError,
    AuditErrorCode,
    AuditKey,
    AuditRecord,
    AuditSink,
    audit_json,
    validate_audit,
)
from teecustody.channel import (
    ChannelOutcome,
    ChannelServer,
    CloseReason,
    EnrollPayload,
    EnvelopeError,
    EnvelopeErrorCode,
    FrameHandler,
    FrameResultBody,
    HandlerError,
    HandlerOk,
    HpkeError,
    HpkeErrorCode,
    IdentityKey,
    OpenAccepted,
    OpenRejected,
    OpenRequest,
    OpenResult,
    OpenSessionPayload,
    OutboundResponse,
    PreKeyPublic,
    PreKeyStore,
    ProcessResult,
    RemoteErrorCode,
    ReplayCache,
    Session,
    SessionInfo,
    SessionOpener,
    SessionReject,
    SessionRejectCode,
    SessionTable,
    T2cSealer,
    build_bundle,
    codec,
    hpke,
    ports,
)
from teecustody.channel.codec import (
    CLIENT_ID_PATTERN,
    ERROR_CODE_PATTERN,
    HEX32_PATTERN,
    INSTANCE_ID_PATTERN,
    MAX_SEQ,
    MAX_UNIX_S,
    OP_NAME_PATTERN,
    FrameAad,
    FrameRequestEnvelope,
    FrameResultEnvelope,
    OpenAad,
    OpenRequestEnvelope,
    OpenResultAad,
    OpenResultBody,
    OpenResultEnvelope,
    PreKeyBundle,
    PreKeyEntry,
    decode_bundle,
    decode_open_payload,
    decode_open_result_plaintext,
    decode_request,
    decode_response,
    encode_bundle,
    encode_frame_aad,
    encode_frame_result_plaintext,
    encode_open_result_aad,
    encode_open_result_plaintext,
    encode_response_envelope,
    hpke_info,
    prekey_signing_message,
)
from teecustody.channel.hpke import (
    AEAD_ID,
    EXPORT_C2T,
    EXPORT_LENGTH,
    EXPORT_T2C,
    KDF_ID,
    KEM_ID,
    OpenedHpke,
    generate_keypair,
    open_base,
)
from teecustody.channel.session import _nonce, open_frame
from teecustody.config import BoundaryLimits, ChannelParams, ConfigError, ConfigErrorCode
from teecustody.obs import AllowListedLogger
from teecustody.queue import (
    CURSOR_PATTERN,
    RELAY_ID_PATTERN,
    PublishedBundle,
    PublishedResponse,
    Queue,
    QueueError,
    QueueErrorCode,
    QueueMessage,
    RelayQueue,
    ResponsePage,
    WorkloadQueue,
)
from teecustody.runtime import RunLoop, StopCode, TickReport, WorkloadStopped
from teecustody.secrets import Secret, SecretError, SecretErrorCode
from teecustody.wire import CanonicalValue, DecodeLimits

# --- criterion 1: names import from their package roots ----------------------------------------

PACKAGE_EXPORTS: dict[str, frozenset[str]] = {
    "teecustody.channel": frozenset(
        {
            "IdentityKey",
            "ChannelServer",
            "ChannelOutcome",
            "ProcessResult",
            "OutboundResponse",
            "CloseReason",
            "EnrollPayload",
            "FrameHandler",
            "FrameResultBody",
            "HandlerError",
            "HandlerOk",
            "OpenAccepted",
            "OpenRejected",
            "OpenRequest",
            "OpenResult",
            "OpenSessionPayload",
            "RemoteErrorCode",
            "SessionInfo",
            "SessionOpener",
            "EnvelopeError",
            "EnvelopeErrorCode",
            "PreKeyStore",
            "PreKeyPublic",
            "build_bundle",
            "ReplayCache",
            "Session",
            "SessionTable",
            "SessionReject",
            "SessionRejectCode",
            "T2cSealer",
            "HpkeError",
            "HpkeErrorCode",
        }
    ),
    "teecustody.queue": frozenset(
        {
            "RELAY_ID_PATTERN",
            "CURSOR_PATTERN",
            "QueueErrorCode",
            "QueueError",
            "PublishedBundle",
            "QueueMessage",
            "PublishedResponse",
            "ResponsePage",
            "WorkloadQueue",
            "RelayQueue",
            "Queue",
        }
    ),
    "teecustody.audit": frozenset(
        {
            "AuditClass",
            "AUDIT_ID_PATTERN",
            "MAX_COUNT",
            "AuditKey",
            "AuditRecord",
            "AppendResult",
            "AuditErrorCode",
            "AuditError",
            "AuditSink",
            "validate_audit",
            "audit_json",
            "AggregateOutcome",
            "AuditEmitter",
        }
    ),
    "teecustody.runtime": frozenset({"StopCode", "WorkloadStopped", "TickReport", "RunLoop"}),
    "teecustody.secrets": frozenset({"Secret", "SecretError", "SecretErrorCode"}),
}

# Module-level names that are part of the frozen API without a package-root export.
MODULE_NAMES: dict[str, tuple[str, ...]] = {
    "teecustody.config": ("ConfigErrorCode", "ConfigError", "ChannelParams", "BoundaryLimits"),
    "teecustody.attest.claims": ("IMAGE_DIGEST_PATTERN", "own_image_digest"),
    "teecustody.channel.codec": (
        "EnvelopeErrorCode",
        "EnvelopeError",
        "HEX32_PATTERN",
        "CLIENT_ID_PATTERN",
        "INSTANCE_ID_PATTERN",
        "OP_NAME_PATTERN",
        "ERROR_CODE_PATTERN",
        "MAX_UNIX_S",
        "MAX_SEQ",
        "PreKeyEntry",
        "PreKeyBundle",
        "OpenAad",
        "FrameAad",
        "OpenResultAad",
        "OpenRequestEnvelope",
        "FrameRequestEnvelope",
        "OpenResultEnvelope",
        "FrameResultEnvelope",
        "OpenResultBody",
        "OpenSessionPayload",
        "EnrollPayload",
        "encode_bundle",
        "decode_bundle",
        "decode_request",
        "decode_open_payload",
        "encode_open_result_aad",
        "encode_frame_aad",
        "encode_open_result_plaintext",
        "encode_frame_result_plaintext",
        "encode_response_envelope",
        "decode_response",
        "decode_open_result_plaintext",
        "prekey_signing_message",
        "hpke_info",
    ),
    "teecustody.channel.hpke": (
        "KEM_ID",
        "KDF_ID",
        "AEAD_ID",
        "EXPORT_C2T",
        "EXPORT_T2C",
        "EXPORT_LENGTH",
        "HpkeErrorCode",
        "HpkeError",
        "generate_keypair",
        "OpenedHpke",
        "open_base",
    ),
    "teecustody.channel.session": ("open_frame", "_nonce"),
}

NOT_EXPORTED_FROM_CHANNEL = (
    "open_frame",
    "_nonce",
    "open_base",
    "generate_keypair",
    "encode_bundle",
    "decode_bundle",
    "decode_request",
    "decode_open_payload",
    "encode_open_result_aad",
    "encode_frame_aad",
    "encode_open_result_plaintext",
    "encode_frame_result_plaintext",
    "encode_response_envelope",
    "decode_response",
    "decode_open_result_plaintext",
    "prekey_signing_message",
    "hpke_info",
)


@pytest.mark.parametrize(("package", "names"), PACKAGE_EXPORTS.items(), ids=PACKAGE_EXPORTS.keys())
def test_package_root_exports_exactly_the_api_tl_names(package: str, names: frozenset[str]) -> None:
    module = importlib.import_module(package)
    assert frozenset(module.__all__) == names
    assert len(module.__all__) == len(names)
    for name in names:
        assert hasattr(module, name), f"{package}.{name}"


@pytest.mark.parametrize(
    ("module_name", "name"),
    [(module, name) for module, names in MODULE_NAMES.items() for name in names],
)
def test_module_level_name_exists(module_name: str, name: str) -> None:
    assert hasattr(importlib.import_module(module_name), name), f"{module_name}.{name}"


@pytest.mark.parametrize("name", NOT_EXPORTED_FROM_CHANNEL)
def test_internal_channel_names_are_not_re_exported(name: str) -> None:
    channel = importlib.import_module("teecustody.channel")
    assert name not in channel.__all__
    assert not hasattr(channel, name)


def test_codec_re_exports_the_payload_types_defined_in_ports() -> None:
    assert codec.OpenSessionPayload is ports.OpenSessionPayload
    assert codec.EnrollPayload is ports.EnrollPayload


def test_root_exports_are_the_defining_objects() -> None:
    assert OpenSessionPayload is ports.OpenSessionPayload
    assert EnvelopeError is codec.EnvelopeError
    assert HpkeError is hpke.HpkeError


# --- criterion 1: signatures ------------------------------------------------------------------
# INC-2-API §4.1-§4.13 and API-TL §2 transcribed verbatim.


class _SecretSpec:
    def __init__(self, data: bytes | bytearray | memoryview) -> None: ...
    @classmethod
    def random(cls, length: int) -> Secret: ...
    def __len__(self) -> int: ...
    def reveal(self) -> bytes: ...
    def equals(self, other: Secret | bytes) -> bool: ...
    def wipe(self) -> None: ...
    @property
    def wiped(self) -> bool: ...
    def __enter__(self) -> Secret: ...
    def __exit__(self, *exc: object) -> None: ...


class _IdentityKeySpec:
    def sign(self, message: bytes) -> bytes: ...


def _spec_own_image_digest(token: AttestationToken, *, max_token_bytes: int) -> str: ...


class _ConfigErrorSpec:
    def __init__(self, code: ConfigErrorCode, field: str) -> None: ...


def _spec_encode_bundle(b: PreKeyBundle) -> bytes: ...
def _spec_decode_bundle(data: bytes, limits: DecodeLimits) -> PreKeyBundle: ...
def _spec_decode_request(
    body: bytes, limits: BoundaryLimits
) -> OpenRequestEnvelope | FrameRequestEnvelope: ...
def _spec_decode_open_payload(
    pt: Secret, limits: DecodeLimits
) -> OpenSessionPayload | EnrollPayload: ...
def _spec_encode_open_result_aad(aad: OpenResultAad) -> bytes: ...
def _spec_encode_frame_aad(aad: FrameAad) -> bytes: ...
def _spec_encode_open_result_plaintext(result: OpenAccepted | OpenRejected) -> bytes: ...
def _spec_encode_frame_result_plaintext(re: int, body: HandlerOk | HandlerError) -> bytes: ...
def _spec_encode_response_envelope(
    kind: Literal["open_result", "frame_result"], aad_bytes: bytes, ct: bytes
) -> bytes: ...
def _spec_decode_response(
    body: bytes, limits: BoundaryLimits
) -> OpenResultEnvelope | FrameResultEnvelope: ...
def _spec_decode_open_result_plaintext(
    pt: bytes, aad: OpenResultAad, limits: DecodeLimits
) -> OpenResultBody: ...
def _spec_prekey_signing_message(
    instance_id: str, prekey_id: int, pub: bytes, not_after: int, image_digest: str
) -> bytes: ...
def _spec_hpke_info(ik_pub: bytes, prekey_id: int) -> bytes: ...


def _spec_generate_keypair() -> tuple[Secret, bytes]: ...
def _spec_open_base(
    private_key: Secret, enc: bytes, info: bytes, aad: bytes, ct: bytes
) -> OpenedHpke: ...


class _PreKeyStoreSpec:
    def __init__(
        self,
        *,
        instance_id: str,
        identity: IdentityKey,
        image_digest: str,
        params: ChannelParams,
        clock: Callable[[], float],
    ) -> None: ...
    def top_up(self) -> int: ...
    def expire(self) -> int: ...
    def public_entries(self) -> tuple[PreKeyPublic, ...]: ...
    def take(self, prekey_id: int) -> Secret: ...
    def consumed_since(self, since: float) -> int: ...
    def destroy_all(self) -> None: ...


def _spec_build_bundle(
    *,
    instance_id: str,
    token: AttestationToken,
    ik_pub: bytes,
    prekeys: Sequence[PreKeyPublic],
    published_at: int,
) -> bytes: ...


class _SessionOpenerSpec:
    def open(self, request: OpenRequest) -> OpenResult: ...
    def closed(self, session: SessionInfo, reason: CloseReason) -> None: ...


class _FrameHandlerSpec:
    def handle(self, session: SessionInfo, op: str, payload: CanonicalValue) -> FrameResultBody: ...


class _ReplayCacheSpec:
    def __init__(self, *, skew_s: int, max_entries: int, clock: Callable[[], float]) -> None: ...
    def seen(self, aad_client_id: str, request_id: bytes) -> bool: ...
    def record(self, aad_client_id: str, request_id: bytes, timestamp: int) -> None: ...


class _T2cSealerSpec:
    def __init__(self, sk_t2c: Secret) -> None: ...
    def seal_open_result(self, aad: OpenResultAad, plaintext: bytes) -> tuple[bytes, bytes]: ...
    def seal_frame_result(
        self, op: str, session_id: bytes, plaintext: bytes
    ) -> tuple[bytes, bytes]: ...
    def wipe(self) -> None: ...


class _SessionSpec:
    def open_c2t(self, aad: FrameAad, aad_bytes: bytes, ct: bytes, now: float) -> Secret: ...
    def seal_open_result(self, request_id: bytes, plaintext: bytes) -> tuple[bytes, bytes]: ...
    def seal_t2c(self, op: str, plaintext: bytes) -> tuple[FrameAad, bytes, bytes]: ...


class _SessionTableSpec:
    def __init__(
        self,
        *,
        instance_id: str,
        max_sessions: int,
        idle_timeout_s: int,
        evict_min_idle_s: int,
        on_close: Callable[[SessionInfo, CloseReason], None],
        clock: Callable[[], float],
    ) -> None: ...
    def create(
        self, *, session_id: bytes, client_id: str, sk_c2t: Secret, t2c: T2cSealer
    ) -> Session: ...
    def get(self, session_id: bytes) -> Session | None: ...
    def close(self, session_id: bytes, reason: CloseReason) -> None: ...
    def expire_idle(self) -> int: ...
    def close_all(self) -> None: ...


def _spec_open_frame(
    key: Secret, last_seq: int, aad: FrameAad, aad_bytes: bytes, ct: bytes
) -> Secret: ...
def _spec_nonce(seq: int) -> bytes: ...


class _ChannelServerSpec:
    def __init__(
        self,
        *,
        instance_id: str,
        ik_pub: bytes,
        prekeys: PreKeyStore,
        sessions: SessionTable,
        replay: ReplayCache,
        opener: SessionOpener,
        handler: FrameHandler,
        audit: AuditEmitter,
        params: ChannelParams,
        limits: BoundaryLimits,
        clock: Callable[[], float],
        rng: Callable[[int], bytes],
        logger: AllowListedLogger,
    ) -> None: ...
    def process(self, body: bytes) -> ProcessResult: ...


class _WorkloadQueueSpec:
    def publish_bundle(self, instance_id: str, bundle: bytes, expires_at: int) -> None: ...
    def pull_requests(
        self, instance_id: str, max_messages: int, wait_s: float
    ) -> list[QueueMessage]: ...
    def ack(self, message_id: str) -> None: ...
    def publish_response(self, client_id: str, request_id: str, body: bytes) -> None: ...
    def withdraw_bundle(self, instance_id: str) -> None: ...


class _RelayQueueSpec:
    def list_bundles(self, max_bundles: int) -> list[PublishedBundle]: ...
    def publish_request(self, instance_id: str, request_id: str, body: bytes) -> str: ...
    def pull_responses(
        self, client_id: str, after: str | None, max_messages: int
    ) -> ResponsePage: ...


class _AuditSinkSpec:
    def append(self, key: AuditKey, record: AuditRecord) -> AppendResult: ...


def _spec_validate_audit(key: AuditKey, record: AuditRecord) -> None: ...
def _spec_audit_json(record: AuditRecord) -> bytes: ...


class _AuditEmitterSpec:
    def __init__(
        self,
        sink: AuditSink,
        *,
        interval_s: int,
        alert_cap: int,
        clock: Callable[[], float],
        rng: Callable[[int], bytes],
        logger: AllowListedLogger,
    ) -> None: ...
    def count(self, outcome: AggregateOutcome) -> None: ...
    def pre_principal_alert(
        self,
        outcome: str,
        *,
        subject_client_id: str,
        request_id: str | None = None,
        epoch: int | None = None,
        recovery_id: str | None = None,
    ) -> None: ...
    def alert(
        self,
        outcome: str,
        *,
        request_id: str | None = None,
        interval: tuple[int, int] | None = None,
    ) -> None: ...
    def tick(self) -> None: ...
    def close(self) -> None: ...


class _RunLoopSpec:
    def __init__(
        self,
        *,
        launcher: Launcher,
        queue: WorkloadQueue,
        audit_sink: AuditSink,
        opener: SessionOpener,
        handler: FrameHandler,
        audience: str,
        token_type: str,
        params: ChannelParams = ChannelParams(),  # noqa: B008 - transcribed default
        limits: BoundaryLimits = BoundaryLimits(),  # noqa: B008 - transcribed default
        clock: Callable[[], float] = time.time,
        rng: Callable[[int], bytes] = os.urandom,
        logger: AllowListedLogger | None = None,
    ) -> None: ...
    @property
    def instance_id(self) -> str: ...
    def start(self) -> None: ...
    def tick(self) -> TickReport: ...
    def run(self, stop: threading.Event) -> None: ...
    def shutdown(self) -> None: ...


def _signature(obj: object) -> inspect.Signature:
    target = obj.fget if isinstance(obj, property) else obj
    assert callable(target)
    return inspect.signature(target, eval_str=True)


def _methods(actual: type, spec: type, names: Sequence[str]) -> dict[str, tuple[object, object]]:
    return {f"{actual.__name__}.{n}": (getattr(actual, n), getattr(spec, n)) for n in names}


FROZEN_SIGNATURES: dict[str, tuple[object, object]] = {
    **_methods(
        Secret,
        _SecretSpec,
        ["__init__", "random", "__len__", "reveal", "equals", "wipe", "wiped"],
    ),
    **_methods(Secret, _SecretSpec, ["__enter__", "__exit__"]),
    **_methods(IdentityKey, _IdentityKeySpec, ["sign"]),
    "own_image_digest": (own_image_digest, _spec_own_image_digest),
    "ConfigError.__init__": (ConfigError.__init__, _ConfigErrorSpec.__init__),
    "encode_bundle": (encode_bundle, _spec_encode_bundle),
    "decode_bundle": (decode_bundle, _spec_decode_bundle),
    "decode_request": (decode_request, _spec_decode_request),
    "decode_open_payload": (decode_open_payload, _spec_decode_open_payload),
    "encode_open_result_aad": (encode_open_result_aad, _spec_encode_open_result_aad),
    "encode_frame_aad": (encode_frame_aad, _spec_encode_frame_aad),
    "encode_open_result_plaintext": (
        encode_open_result_plaintext,
        _spec_encode_open_result_plaintext,
    ),
    "encode_frame_result_plaintext": (
        encode_frame_result_plaintext,
        _spec_encode_frame_result_plaintext,
    ),
    "encode_response_envelope": (encode_response_envelope, _spec_encode_response_envelope),
    "decode_response": (decode_response, _spec_decode_response),
    "decode_open_result_plaintext": (
        decode_open_result_plaintext,
        _spec_decode_open_result_plaintext,
    ),
    "prekey_signing_message": (prekey_signing_message, _spec_prekey_signing_message),
    "hpke_info": (hpke_info, _spec_hpke_info),
    "generate_keypair": (generate_keypair, _spec_generate_keypair),
    "open_base": (open_base, _spec_open_base),
    **_methods(
        PreKeyStore,
        _PreKeyStoreSpec,
        [
            "__init__",
            "top_up",
            "expire",
            "public_entries",
            "take",
            "consumed_since",
            "destroy_all",
        ],
    ),
    "build_bundle": (build_bundle, _spec_build_bundle),
    **_methods(SessionOpener, _SessionOpenerSpec, ["open", "closed"]),
    **_methods(FrameHandler, _FrameHandlerSpec, ["handle"]),
    **_methods(ReplayCache, _ReplayCacheSpec, ["__init__", "seen", "record"]),
    **_methods(
        T2cSealer,
        _T2cSealerSpec,
        ["__init__", "seal_open_result", "seal_frame_result", "wipe"],
    ),
    **_methods(Session, _SessionSpec, ["open_c2t", "seal_open_result", "seal_t2c"]),
    **_methods(
        SessionTable,
        _SessionTableSpec,
        ["__init__", "create", "get", "close", "expire_idle", "close_all"],
    ),
    "open_frame": (open_frame, _spec_open_frame),
    "_nonce": (_nonce, _spec_nonce),
    **_methods(ChannelServer, _ChannelServerSpec, ["__init__", "process"]),
    **_methods(
        WorkloadQueue,
        _WorkloadQueueSpec,
        ["publish_bundle", "pull_requests", "ack", "publish_response", "withdraw_bundle"],
    ),
    **_methods(RelayQueue, _RelayQueueSpec, ["list_bundles", "publish_request", "pull_responses"]),
    **_methods(AuditSink, _AuditSinkSpec, ["append"]),
    "validate_audit": (validate_audit, _spec_validate_audit),
    "audit_json": (audit_json, _spec_audit_json),
    **_methods(
        AuditEmitter,
        _AuditEmitterSpec,
        ["__init__", "count", "pre_principal_alert", "alert", "tick", "close"],
    ),
    **_methods(
        RunLoop,
        _RunLoopSpec,
        ["__init__", "instance_id", "start", "tick", "run", "shutdown"],
    ),
}


@pytest.mark.parametrize(
    ("actual", "spec"), FROZEN_SIGNATURES.values(), ids=FROZEN_SIGNATURES.keys()
)
def test_full_signature_equals_api_transcription(actual: object, spec: object) -> None:
    assert _signature(actual) == _signature(spec)


def test_queue_is_the_union_protocol_of_both_sides() -> None:
    for protocol in (WorkloadQueue, RelayQueue, Queue, AuditSink, SessionOpener, FrameHandler):
        assert getattr(protocol, "_is_protocol", False), protocol.__name__
    assert Queue.__bases__[:2] == (WorkloadQueue, RelayQueue)
    assert typing.Protocol in Queue.__bases__


def test_session_attributes_are_annotated_as_specified() -> None:
    hints = typing.get_type_hints(Session)
    spec = {"session_id": bytes, "client_id": str, "opened_at": float, "last_activity": float}
    assert {name: hints.get(name) for name in spec} == spec


def test_result_type_aliases_are_unions_of_the_specified_types() -> None:
    assert OpenResult.__value__ == OpenAccepted | OpenRejected
    assert FrameResultBody.__value__ == HandlerOk | HandlerError


# Every exception carries only its code; str(err) is the code value (ConfigError: "<code>:<field>").
CODE_ERRORS: list[tuple[type[Exception], type[StrEnum]]] = [
    (SecretError, SecretErrorCode),
    (EnvelopeError, EnvelopeErrorCode),
    (HpkeError, HpkeErrorCode),
    (SessionReject, SessionRejectCode),
    (QueueError, QueueErrorCode),
    (AuditError, AuditErrorCode),
    (WorkloadStopped, StopCode),
]


@pytest.mark.parametrize(("error", "codes"), CODE_ERRORS, ids=[e.__name__ for e, _ in CODE_ERRORS])
def test_code_only_exception_signature_and_str(
    error: type[Exception], codes: type[StrEnum]
) -> None:
    actual = inspect.signature(error.__init__, eval_str=True)
    assert list(actual.parameters) == ["self", "code"]
    assert actual.parameters["code"].annotation is codes
    assert actual.parameters["code"].kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
    assert actual.return_annotation is None
    for code in codes:
        err = error(code)  # type: ignore[call-arg]
        assert err.code is code  # type: ignore[attr-defined]
        assert str(err) == code.value
        assert err.args == (code.value,)
        assert vars(err) == {"code": code}


@pytest.mark.parametrize("code", list(ConfigErrorCode))
def test_config_error_str_is_code_and_field(code: ConfigErrorCode) -> None:
    err = ConfigError(code, "pull_wait_s")
    assert err.code is code
    assert err.field == "pull_wait_s"
    assert str(err) == f"{code.value}:pull_wait_s"
    assert vars(err) == {"code": code, "field": "pull_wait_s"}


# --- criterion 2: enums, constants, dataclasses, patterns --------------------------------------


ENUMS: list[tuple[type[StrEnum], list[str]]] = [
    (SecretErrorCode, ["WIPED", "INVALID_LENGTH", "FORBIDDEN"]),
    (ConfigErrorCode, ["INVALID_PARAMS", "INVALID_LIMITS"]),
    (EnvelopeErrorCode, ["TOO_LARGE", "INVALID"]),
    (HpkeErrorCode, ["OPEN_FAILED", "INVALID_KEY"]),
    (
        RemoteErrorCode,
        [
            "INVALID_FRAME",
            "AUTHENTICATION_FAILED",
            "REPLAYED_OR_OUT_OF_ORDER",
            "UNKNOWN_CLIENT",
            "UNKNOWN_OPERATION",
            "NOT_AUTHORIZED",
            "LIMIT_EXCEEDED",
            "RECORD_NOT_FOUND",
            "BACKEND_UNAVAILABLE",
            "INTERNAL",
        ],
    ),
    (
        CloseReason,
        [
            "CLIENT_CLOSE",
            "IDLE_TIMEOUT",
            "REPLACED",
            "SEQUENCE_EXHAUSTED",
            "SHUTDOWN",
            "EVICTED",
            "OPEN_ABORTED",
        ],
    ),
    (SessionRejectCode, ["SEQ_REJECTED", "AUTH_FAILED", "EXHAUSTED", "USED"]),
    (ChannelOutcome, ["SESSION_OPENED", "OPEN_REJECTED", "FRAME_ACCEPTED", "SESSION_CLOSED"]),
    (QueueErrorCode, ["INVALID_ARGUMENT", "NOT_FOUND", "CONFLICT", "UNAVAILABLE", "INTERNAL"]),
    (AuditClass, ["EVENT", "ALERT", "AGGREGATE", "RELEASE"]),
    (AppendResult, ["CREATED", "ALREADY_EXISTS"]),
    (AuditErrorCode, ["INVALID_ARGUMENT", "UNAVAILABLE"]),
    (
        AggregateOutcome,
        [
            "REQUEST_INVALID",
            "REQUEST_WRONG_INSTANCE",
            "PREKEY_UNKNOWN",
            "REQUEST_STALE",
            "REQUEST_REPLAYED",
            "OPEN_FAILED",
            "OPEN_PAYLOAD_INVALID",
            "OPEN_REJECTED",
            "SESSION_UNKNOWN",
            "FRAME_SEQ_REJECTED",
            "FRAME_AUTH_FAILED",
            "CHANNEL_LIMIT_EXCEEDED",
        ],
    ),
    (
        StopCode,
        ["ATTESTATION_EXPIRED", "DIGEST_CHANGED", "PREKEY_IDS_EXHAUSTED", "QUEUE_UNAVAILABLE"],
    ),
]


@pytest.mark.parametrize(("enum", "values"), ENUMS, ids=[e.__name__ for e, _ in ENUMS])
def test_enum_members_equal_api(enum: type[StrEnum], values: list[str]) -> None:
    assert issubclass(enum, StrEnum)
    assert [(member.name, member.value) for member in enum] == [(v, v) for v in values]


CONSTANTS: list[tuple[str, object, object]] = [
    ("MAX_UNIX_S", MAX_UNIX_S, 2**53 - 1),
    ("MAX_SEQ", MAX_SEQ, 2**53 - 1),
    ("KEM_ID", KEM_ID, 0x0020),
    ("KDF_ID", KDF_ID, 0x0001),
    ("AEAD_ID", AEAD_ID, 0x0002),
    ("EXPORT_C2T", EXPORT_C2T, b"c2t"),
    ("EXPORT_T2C", EXPORT_T2C, b"t2c"),
    ("EXPORT_LENGTH", EXPORT_LENGTH, 32),
    ("MAX_COUNT", MAX_COUNT, 2**53 - 1),
]


@pytest.mark.parametrize(("name", "actual", "expected"), CONSTANTS, ids=[c[0] for c in CONSTANTS])
def test_constant_equals_api(name: str, actual: object, expected: object) -> None:
    assert type(actual) is type(expected), name
    assert actual == expected, name


# (name, compiled pattern, transcribed source, a value the pattern must accept)
PATTERNS: list[tuple[str, re.Pattern[str], str, str]] = [
    ("HEX32_PATTERN", HEX32_PATTERN, r"[0-9a-f]{32}", "0123456789abcdef" * 2),
    ("OP_NAME_PATTERN", OP_NAME_PATTERN, r"[a-z][a-z0-9_.]{0,63}", "test.echo"),
    ("ERROR_CODE_PATTERN", ERROR_CODE_PATTERN, r"[A-Z][A-Z0-9_]{0,63}", "INVALID_FRAME"),
    ("IMAGE_DIGEST_PATTERN", IMAGE_DIGEST_PATTERN, r"sha256:[0-9a-f]{64}", "sha256:" + "ab" * 32),
    ("RELAY_ID_PATTERN", RELAY_ID_PATTERN, r"[0-9a-f]{32}", "cd" * 16),
    ("CURSOR_PATTERN", CURSOR_PATTERN, r"[A-Za-z0-9_-]{1,128}", "Ab_-09"),
    (
        "AUDIT_ID_PATTERN",
        AUDIT_ID_PATTERN,
        r"[A-Za-z0-9_-]{1,128}(/[A-Za-z0-9_-]{1,64}){0,2}",
        "1800000000000/OPEN_FAILED/0123456789abcdef",
    ),
]


@pytest.mark.parametrize(
    ("name", "pattern", "source", "valid"), PATTERNS, ids=[p[0] for p in PATTERNS]
)
def test_pattern_is_unanchored_and_fullmatch_rejects_trailing_newline(
    name: str, pattern: re.Pattern[str], source: str, valid: str
) -> None:
    assert pattern.pattern == source, name
    assert "^" not in pattern.pattern
    assert "$" not in pattern.pattern
    assert pattern.flags == re.compile("").flags
    assert pattern.fullmatch(valid) is not None
    assert pattern.fullmatch(valid + "\n") is None


def test_id_patterns_are_the_same_object() -> None:
    assert CLIENT_ID_PATTERN is HEX32_PATTERN
    assert INSTANCE_ID_PATTERN is HEX32_PATTERN


M = dataclasses.MISSING
ENVELOPE = DecodeLimits(max_bytes=65536, max_depth=2, max_items=16)

type _Options = tuple[bool, bool, bool, bool]  # (frozen, slots, kw_only, eq)
type _Field = tuple[str, object, object, bool]  # (name, type, default, repr)

DATACLASSES: list[tuple[type, _Options, list[_Field]]] = [
    (
        ChannelParams,
        (True, True, True, True),
        [
            ("prekey_ttl_s", int, 3600, True),
            ("prekey_batch", int, 100, True),
            ("prekey_low_water", int, 20, True),
            ("request_skew_s", int, 300, True),
            ("idle_timeout_s", int, 900, True),
            ("refresh_margin_s", int, 300, True),
        ],
    ),
    (
        BoundaryLimits,
        (True, True, True, True),
        [
            ("max_token_bytes", int, 16384, True),
            ("max_request_bytes", int, 65536, True),
            ("envelope_decode", DecodeLimits, ENVELOPE, True),
            ("aad_decode", DecodeLimits, DecodeLimits(512, 2, 16), True),
            ("open_payload_decode", DecodeLimits, DecodeLimits(1024, 2, 16), True),
            ("payload_decode", DecodeLimits, DecodeLimits(32768, 16, 4096), True),
            ("pull_max_messages", int, 32, True),
            ("pull_wait_s", float, 1.0, True),
            ("max_sessions", int, 1024, True),
            ("session_evict_min_idle_s", int, 60, True),
            ("replay_cache_max_entries", int, 100_000, True),
            ("audit_aggregate_interval_s", int, 60, True),
            ("audit_alert_cap", int, 100, True),
            ("prekey_burn_alert_threshold", int, 500, True),
            ("attestation_retry_min_s", int, 30, True),
            ("attestation_retry_max_s", int, 300, True),
            ("bundle_republish_min_interval_s", int, 5, True),
        ],
    ),
    (
        PreKeyEntry,
        (True, True, False, True),
        [
            ("id", int, M, True),
            ("pub", bytes, M, True),
            ("not_after", int, M, True),
            ("sig", bytes, M, True),
        ],
    ),
    (
        PreKeyBundle,
        (True, True, False, True),
        [
            ("instance_id", str, M, True),
            ("token", str, M, False),
            ("ik_pub", bytes, M, True),
            ("published_at", int, M, True),
            ("prekeys", tuple[PreKeyEntry, ...], M, True),
        ],
    ),
    (
        OpenAad,
        (True, True, False, True),
        [
            ("client_id", str, M, True),
            ("instance_id", str, M, True),
            ("prekey_id", int, M, True),
            ("request_id", bytes, M, True),
            ("timestamp", int, M, True),
        ],
    ),
    (
        FrameAad,
        (True, True, False, True),
        [("session_id", bytes, M, True), ("seq", int, M, True), ("op", str, M, True)],
    ),
    (
        OpenResultAad,
        (True, True, False, True),
        [("session_id", bytes | None, M, True), ("request_id", bytes, M, True)],
    ),
    (
        OpenRequestEnvelope,
        (True, True, False, True),
        [
            ("aad_bytes", bytes, M, True),
            ("aad", OpenAad, M, True),
            ("enc", bytes, M, True),
            ("ct", bytes, M, False),
        ],
    ),
    (
        FrameRequestEnvelope,
        (True, True, False, True),
        [("aad_bytes", bytes, M, True), ("aad", FrameAad, M, True), ("ct", bytes, M, False)],
    ),
    (
        OpenResultEnvelope,
        (True, True, False, True),
        [("aad_bytes", bytes, M, True), ("aad", OpenResultAad, M, True), ("ct", bytes, M, False)],
    ),
    (
        FrameResultEnvelope,
        (True, True, False, True),
        [("aad_bytes", bytes, M, True), ("aad", FrameAad, M, True), ("ct", bytes, M, False)],
    ),
    (
        OpenResultBody,
        (True, True, False, True),
        [
            ("ok", bool, M, True),
            ("payload", CanonicalValue, None, False),
            ("error", str | None, None, True),
        ],
    ),
    (
        OpenSessionPayload,
        (True, True, False, False),
        [("cs", Secret, M, True), ("key_id", bytes, M, True), ("epoch", int, M, True)],
    ),
    (EnrollPayload, (True, True, False, True), []),
    (
        OpenedHpke,
        (True, True, False, False),
        [("plaintext", Secret, M, True), ("sk_c2t", Secret, M, True), ("sk_t2c", Secret, M, True)],
    ),
    (
        PreKeyPublic,
        (True, True, False, True),
        [
            ("id", int, M, True),
            ("pub", bytes, M, True),
            ("not_after", int, M, True),
            ("sig", bytes, M, True),
        ],
    ),
    (
        OpenRequest,
        (True, True, False, False),
        [
            ("claimed_client_id", str | None, M, True),
            ("request_id", bytes, M, True),
            ("instance_id", str, M, True),
            ("session_id", bytes, M, True),
            ("payload", OpenSessionPayload | EnrollPayload, M, False),
        ],
    ),
    (
        OpenAccepted,
        (True, True, False, True),
        [("client_id", str, M, True), ("payload", CanonicalValue, M, False)],
    ),
    (OpenRejected, (True, True, False, True), [("error", RemoteErrorCode, M, True)]),
    (
        SessionInfo,
        (True, True, False, True),
        [
            ("client_id", str, M, True),
            ("session_id", bytes, M, True),
            ("instance_id", str, M, True),
        ],
    ),
    (HandlerOk, (True, True, False, True), [("payload", CanonicalValue, M, False)]),
    (HandlerError, (True, True, False, True), [("error", RemoteErrorCode, M, True)]),
    (
        OutboundResponse,
        (True, True, False, True),
        [("client_id", str, M, True), ("body", bytes, M, False)],
    ),
    (
        ProcessResult,
        (True, True, False, True),
        [("outcome", str, M, True), ("response", OutboundResponse | None, M, True)],
    ),
    (
        PublishedBundle,
        (True, True, False, True),
        [("instance_id", str, M, True), ("bundle", bytes, M, False)],
    ),
    (
        QueueMessage,
        (True, True, False, True),
        [
            ("message_id", str, M, True),
            ("request_id", str, M, True),
            ("body", bytes, M, False),
            ("published_at", float, M, True),
        ],
    ),
    (
        PublishedResponse,
        (True, True, False, True),
        [("request_id", str, M, True), ("body", bytes, M, False)],
    ),
    (
        ResponsePage,
        (True, True, False, True),
        [("responses", tuple[PublishedResponse, ...], M, True), ("next", str | None, M, True)],
    ),
    (
        AuditKey,
        (True, True, False, True),
        [("record_class", AuditClass, M, True), ("id", str, M, True)],
    ),
    (
        AuditRecord,
        (True, True, True, True),
        [
            ("outcome", str, M, True),
            ("ts", int, M, True),
            ("interval_start", int | None, None, True),
            ("interval_end", int | None, None, True),
            ("actor_client_id", str | None, None, True),
            ("subject_client_id", str | None, None, True),
            ("recovery_id", str | None, None, True),
            ("request_id", str | None, None, True),
            ("session_id", str | None, None, True),
            ("prekey_id", int | None, None, True),
            ("epoch", int | None, None, True),
            ("count", int | None, None, True),
        ],
    ),
    (
        TickReport,
        (True, True, False, True),
        [
            ("refresh", RefreshOutcome | None, M, True),
            ("bundle_published", bool, M, True),
            ("processed", int, M, True),
        ],
    ),
]


@pytest.mark.parametrize(
    ("cls", "options", "fields"), DATACLASSES, ids=[c.__name__ for c, _, _ in DATACLASSES]
)
def test_dataclass_options_and_fields_equal_api(
    cls: type, options: _Options, fields: list[_Field]
) -> None:
    params = cls.__dataclass_params__  # type: ignore[attr-defined]
    assert (params.frozen, params.slots, params.kw_only, params.eq) == options
    assert params.order is False
    assert params.unsafe_hash is False
    hints = typing.get_type_hints(cls)
    actual = [(f.name, hints[f.name], f.default, f.repr) for f in dataclasses.fields(cls)]
    assert actual == fields
    assert all(f.default_factory is M for f in dataclasses.fields(cls))


SENTINEL = "SENTINEL-PLAINTEXT-7f3a"


@pytest.mark.parametrize(
    "value",
    [
        HandlerOk(payload={"body": SENTINEL}),
        OpenAccepted(client_id="0" * 32, payload={"body": SENTINEL}),
        OpenResultBody(ok=True, payload={"body": SENTINEL}),
        OpenRequest(
            claimed_client_id="0" * 32,
            request_id=b"\x01" * 16,
            instance_id="1" * 32,
            session_id=b"\x02" * 16,
            payload=OpenSessionPayload(
                cs=Secret(b"\x03" * 32), key_id=SENTINEL.encode()[:16], epoch=7
            ),
        ),
    ],
    ids=["HandlerOk", "OpenAccepted", "OpenResultBody", "OpenRequest"],
)
def test_plaintext_payload_is_not_in_the_default_repr(value: object) -> None:
    assert SENTINEL[:16] not in repr(value)
    assert SENTINEL[:16] not in str(value)


def test_frozen_api_module_files_exist() -> None:
    root = Path(importlib.import_module("teecustody").__file__ or "").parent
    for relative in (
        "secrets/__init__.py",
        "config.py",
        "attest/claims.py",
        "channel/ports.py",
        "channel/codec.py",
        "channel/hpke.py",
        "channel/prekeys.py",
        "channel/bundle.py",
        "channel/replay.py",
        "channel/session.py",
        "channel/server.py",
        "queue/__init__.py",
        "queue/ports.py",
        "audit/__init__.py",
        "audit/ports.py",
        "audit/validate.py",
        "audit/emitter.py",
        "runtime/__init__.py",
        "runtime/run_loop.py",
    ):
        assert (root / relative).is_file(), relative


# --- criterion 7: no teecustody module imports the simulator or the test tree --------------------

_IMPORT_PROBE = """
import importlib, json, sys
importlib.import_module({module!r})
print(json.dumps(sorted(sys.modules)))
"""


@pytest.mark.parametrize(
    "module",
    [
        "teecustody.channel",
        "teecustody.queue",
        "teecustody.audit",
        "teecustody.runtime",
        "teecustody.secrets",
        "teecustody.config",
        "teecustody.attest.claims",
    ],
)
def test_importing_teecustody_never_loads_the_simulator_or_tests(module: str) -> None:
    probe = subprocess.run(  # noqa: S603 - this interpreter, fixed probe source
        [sys.executable, "-c", _IMPORT_PROBE.format(module=module)],
        capture_output=True,
        check=True,
        text=True,
        cwd=Path(__file__).parent.parent,
    )
    loaded = json.loads(probe.stdout)
    assert module in loaded
    forbidden = [
        name
        for name in loaded
        if name.split(".")[0] in {"teecustody_sim", "tests"} or name.startswith("tests.")
    ]
    assert forbidden == []
