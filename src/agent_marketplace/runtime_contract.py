"""Backend-neutral data contracts and fail-closed admission policy.

These types do not provision, attest, or execute a runtime. Integrations must
supply independently verified backend and artifact-review state before use.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timezone
from enum import StrEnum
from zoneinfo import ZoneInfo
from typing import Literal

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic_core import TzInfo
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)


def _has_builtin_timezone(value: datetime) -> bool:
    """Avoid invoking caller-defined tzinfo methods at contract boundaries."""
    return type(value.tzinfo) in (timezone, ZoneInfo, TzInfo)


def _explicit_datetime_input(value: object) -> object:
    """Reject implicit Unix-epoch coercion; require an aware datetime/ISO value."""
    if type(value) is datetime:
        if not _has_builtin_timezone(value):
            raise ValueError("timestamp must use a standard-library timezone")
        return value
    if type(value) is str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO-8601 datetime with a timezone") from exc
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value
    raise ValueError("timestamp must be a datetime or ISO-8601 string with a timezone")


class RuntimeBackend(StrEnum):
    WASM_WASI = "wasm_wasi"
    SANDBOXED_KUBERNETES = "sandboxed_kubernetes"
    MICROVM = "microvm"


BACKEND_REQUIRED_GATES: dict[RuntimeBackend, frozenset[str]] = {
    RuntimeBackend.WASM_WASI: frozenset({
        "runtime_version_pinned", "component_abi_pinned", "host_imports_allowlisted",
        "filesystem_denied", "process_access_denied", "clock_randomness_restricted",
        "fuel_memory_and_io_bounded", "network_denied", "cancellation_verified",
        "cross_run_cleanup_verified",
    }),
    RuntimeBackend.SANDBOXED_KUBERNETES: frozenset({
        "dedicated_pool", "sandbox_runtime_verified", "host_access_denied",
        "nonroot_readonly_pod", "capabilities_seccomp_restricted",
        "cpu_memory_pid_disk_quotas", "network_policy_enforced",
        "metadata_blocked", "cancellation_verified", "cross_run_cleanup_verified",
    }),
    RuntimeBackend.MICROVM: frozenset({
        "dedicated_kvm_hosts", "vmm_and_guest_pinned", "fresh_vm_per_run",
        "no_shared_writable_storage", "minimal_readonly_guest", "network_denied",
        "resource_quotas_enforced", "vmm_api_vsock_restricted",
        "cancellation_verified", "cross_run_cleanup_verified",
    }),
}


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class TrustedAttestationKey(StrictContract):
    """Operator-managed public signing key with explicit validity and revocation."""

    key_id: str = Field(min_length=1, max_length=160)
    signer_id: str = Field(min_length=1, max_length=160)
    public_key_pem: str = Field(min_length=1, max_length=4096)
    valid_from: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @field_validator("key_id", "signer_id", "public_key_pem", mode="before")
    @classmethod
    def _text_fields_are_builtin(cls, value: object) -> object:
        if type(value) is not str:
            raise ValueError("trusted-key text fields must be built-in strings")
        return value

    @field_validator("valid_from", "expires_at", "revoked_at", mode="before")
    @classmethod
    def _timestamp_input_explicit(cls, value: object) -> object:
        return None if value is None else _explicit_datetime_input(value)

    @field_validator("valid_from", "expires_at", "revoked_at")
    @classmethod
    def _timezone_required(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("key lifecycle timestamps must include a timezone")
        return value

    @field_validator("expires_at")
    @classmethod
    def _expires_after_valid_from(cls, value: datetime, info) -> datetime:
        valid_from = info.data.get("valid_from")
        if valid_from is not None and value <= valid_from:
            raise ValueError("key expiry must be after its valid-from timestamp")
        return value


def _validated_trusted_key(key: object) -> TrustedAttestationKey | None:
    """Revalidate trusted-key records because model_copy(update=...) skips checks."""
    if type(key) is not TrustedAttestationKey:
        return None
    try:
        return TrustedAttestationKey.model_validate(key.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError, RecursionError):
        return None


class ArtifactAttestation(StrictContract):
    """Claim binding an immutable artifact to its review/provenance record.

    `signature` is a base64url Ed25519 signature over the canonical payload;
    constructing this object does not verify it.
    """

    agent_id: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    backend: RuntimeBackend
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance_id: str = Field(min_length=1, max_length=160)
    signer_id: str = Field(min_length=1, max_length=160)
    key_id: str = Field(min_length=1, max_length=160)
    signature_algorithm: Literal["ed25519"]
    signature: str = Field(min_length=1, max_length=256)
    created_at: datetime

    @field_validator(
        "agent_id", "version", "sha256", "provenance_id", "signer_id", "key_id",
        "signature_algorithm", "signature", mode="before",
    )
    @classmethod
    def _text_fields_are_builtin(cls, value: object) -> object:
        if type(value) is not str:
            raise ValueError("attestation text fields must be built-in strings")
        return value

    @field_validator("created_at", mode="before")
    @classmethod
    def _created_at_input_explicit(cls, value: object) -> object:
        return _explicit_datetime_input(value)

    @field_validator("created_at")
    @classmethod
    def _created_at_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("attestation timestamp must include a timezone")
        return value


def _normalized_utc_now(now: datetime | None) -> datetime | None:
    if now is None:
        return datetime.now(UTC)
    if (type(now) is not datetime or not _has_builtin_timezone(now)
            or now.utcoffset() is None):
        return None
    return now.astimezone(UTC)


def attestation_signing_payload(attestation: ArtifactAttestation) -> bytes:
    """Return the stable UTF-8 payload that artifact reviewers must sign."""
    created_at = attestation.created_at
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("attestation timestamp must include a timezone")
    value = {
        "agent_id": attestation.agent_id,
        "backend": attestation.backend.value,
        "created_at": created_at.astimezone(UTC).isoformat(),
        "key_id": attestation.key_id,
        "provenance_id": attestation.provenance_id,
        "sha256": attestation.sha256,
        "signature_algorithm": attestation.signature_algorithm,
        "signer_id": attestation.signer_id,
        "version": attestation.version,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def verify_attestation_signature(
    attestation: ArtifactAttestation,
    trusted_keys: Mapping[str, TrustedAttestationKey],
    *,
    now: datetime | None = None,
    maximum_age_seconds: int = 90 * 24 * 60 * 60,
) -> bool:
    """Verify signature, key identity/lifecycle, and attestation freshness.

    `key_id` selects a trusted operator-provisioned record. Unknown keys,
    signer/key mismatch, keys outside their validity window, revoked keys,
    malformed signatures, future/stale payload timestamps, or a nonpositive age
    bound fail closed. The default attestation age is 90 days.
    """
    if (type(attestation) is not ArtifactAttestation
            or type(trusted_keys) is not dict
            or any(type(key_id) is not str for key_id in trusted_keys)):
        return False
    try:
        attestation = ArtifactAttestation.model_validate(
            attestation.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError, RecursionError):
        return False
    key = _validated_trusted_key(trusted_keys.get(attestation.key_id))
    if (key is None or key.key_id != attestation.key_id
            or key.signer_id != attestation.signer_id):
        return False
    current_time = _normalized_utc_now(now)
    if current_time is None:
        return False
    valid_from = key.valid_from.astimezone(UTC)
    expires_at = key.expires_at.astimezone(UTC)
    attested_at = attestation.created_at
    if attested_at.tzinfo is None or attested_at.utcoffset() is None:
        return False
    attested_at = attested_at.astimezone(UTC)
    if (type(maximum_age_seconds) is not int or maximum_age_seconds < 1
            or current_time < valid_from or current_time >= expires_at
            or attested_at < valid_from or attested_at >= expires_at
            or attested_at > current_time
            or (current_time - attested_at).total_seconds() > maximum_age_seconds
            or (key.revoked_at is not None
                and current_time >= key.revoked_at.astimezone(UTC))):
        return False
    try:
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        encoded = attestation.signature.encode("ascii")
        signature = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        public_key.verify(signature, attestation_signing_payload(attestation))
    except (ValueError, TypeError, UnicodeEncodeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def verify_artifact_bytes(
    attestation: ArtifactAttestation,
    artifact_bytes: bytes,
    *,
    maximum_bytes: int = 50 * 1024 * 1024,
) -> bool:
    """Verify supplied artifact bytes against the signed SHA-256 digest.

    This bounded helper does not retrieve the artifact or provide storage,
    quarantine scanning, or immutability. Callers must enforce those controls
    around byte acquisition and retention.
    """
    if (type(attestation) is not ArtifactAttestation
            or type(artifact_bytes) is not bytes
            or type(maximum_bytes) is not int or maximum_bytes < 0):
        return False
    try:
        attestation = ArtifactAttestation.model_validate(
            attestation.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError, RecursionError):
        return False
    if len(artifact_bytes) > maximum_bytes:
        return False
    return hashlib.sha256(artifact_bytes).hexdigest() == attestation.sha256


class BackendGateEvidence(StrictContract):
    """Structured summary of one independently assessed backend gate test."""

    gate_id: str = Field(min_length=1, max_length=120)
    backend: RuntimeBackend
    environment_id: str = Field(min_length=1, max_length=160)
    policy_revision: str = Field(min_length=1, max_length=80)
    result: Literal["passed"]
    tested_at: datetime
    test_run_id: str = Field(min_length=1, max_length=160)
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator(
        "gate_id", "environment_id", "policy_revision", "result", "test_run_id",
        "report_sha256", mode="before",
    )
    @classmethod
    def _text_fields_are_builtin(cls, value: object) -> object:
        if type(value) is not str:
            raise ValueError("gate-evidence text fields must be built-in strings")
        return value

    @field_validator("tested_at", mode="before")
    @classmethod
    def _tested_at_input_explicit(cls, value: object) -> object:
        return _explicit_datetime_input(value)

    @field_validator("tested_at")
    @classmethod
    def _tested_at_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("gate evidence timestamp must include a timezone")
        return value


class BackendReadiness(StrictContract):
    """Operator-signed, short-lived backend gate result.

    A boolean readiness claim is not evidence by itself. An independent
    assessor signs the backend-specific evidence digests; a distinct operator
    signs the enablement assertion and validity window.
    """

    backend: RuntimeBackend
    environment_id: str = Field(min_length=1, max_length=160)
    generation: int = Field(ge=1, strict=True)
    enabled: bool = Field(strict=True)
    conformance_evidence: dict[str, str]
    policy_revision: str = Field(min_length=1, max_length=80)
    issued_at: datetime
    expires_at: datetime
    signer_id: str = Field(min_length=1, max_length=160)
    key_id: str = Field(min_length=1, max_length=160)
    assessor_id: str = Field(min_length=1, max_length=160)
    assessor_key_id: str = Field(min_length=1, max_length=160)
    assessor_signature: str = Field(min_length=1, max_length=256)
    signature_algorithm: Literal["ed25519"] = "ed25519"
    signature: str = Field(min_length=1, max_length=256)

    @field_validator(
        "environment_id", "policy_revision", "signer_id", "key_id", "assessor_id",
        "assessor_key_id", "assessor_signature", "signature_algorithm", "signature",
        mode="before",
    )
    @classmethod
    def _readiness_text_fields_are_builtin(cls, value: object) -> object:
        if type(value) is not str:
            raise ValueError("readiness text fields must be built-in strings")
        return value

    @field_validator("conformance_evidence", mode="before")
    @classmethod
    def _conformance_evidence_is_builtin_mapping(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("conformance evidence must be a built-in dictionary")
        if any(type(gate) is not str or type(digest) is not str
               for gate, digest in value.items()):
            raise ValueError("conformance evidence keys and digests must be built-in strings")
        return value

    @field_validator("conformance_evidence")
    @classmethod
    def _gate_evidence_is_backend_scoped(
        cls, value: dict[str, str], info,
    ) -> dict[str, str]:
        backend = info.data.get("backend")
        if backend is None:
            raise ValueError("backend is required for conformance evidence")
        allowed = BACKEND_REQUIRED_GATES[backend]
        if set(value) - allowed:
            raise ValueError("conformance evidence contains unknown backend gates")
        if any(not re.fullmatch(r"[0-9a-f]{64}", digest)
               for digest in value.values()):
            raise ValueError("gate evidence must use lowercase SHA-256 digests")
        return value

    @field_validator("issued_at", "expires_at", mode="before")
    @classmethod
    def _readiness_timestamp_input_explicit(cls, value: object) -> object:
        return _explicit_datetime_input(value)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _readiness_timestamps_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("readiness timestamps must include a timezone")
        return value

    @field_validator("expires_at")
    @classmethod
    def _readiness_expiry_after_issue(cls, value: datetime, info) -> datetime:
        issued_at = info.data.get("issued_at")
        if issued_at is not None and value <= issued_at:
            raise ValueError("readiness expiry must be after issue time")
        return value


def backend_conformance_signing_payload(readiness: BackendReadiness) -> bytes:
    """Return canonical evidence payload for an independent conformance assessor."""
    value = {
        "assessor_id": readiness.assessor_id,
        "assessor_key_id": readiness.assessor_key_id,
        "backend": readiness.backend.value,
        "conformance_evidence": readiness.conformance_evidence,
        "environment_id": readiness.environment_id,
        "expires_at": readiness.expires_at.astimezone(UTC).isoformat(),
        "issued_at": readiness.issued_at.astimezone(UTC).isoformat(),
        "policy_revision": readiness.policy_revision,
        "signature_algorithm": readiness.signature_algorithm,
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def backend_readiness_signing_payload(readiness: BackendReadiness) -> bytes:
    """Return canonical signed bytes for a backend readiness gate result."""
    value = readiness.model_dump(mode="json", exclude={"signature"})
    value["issued_at"] = readiness.issued_at.astimezone(UTC).isoformat()
    value["expires_at"] = readiness.expires_at.astimezone(UTC).isoformat()
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def verify_backend_evidence(
    readiness: BackendReadiness,
    evidence: Mapping[str, bytes] | None,
    source_evidence: Mapping[str, bytes] | None,
    *,
    now: datetime | None = None,
    maximum_total_bytes: int = 10 * 1024 * 1024,
    maximum_age_seconds: int = 24 * 60 * 60,
) -> bool:
    """Verify signed reports, source bytes, backend/pool bindings, and freshness.

    The reports and source artifacts must both be supplied and match their
    signed digests. Their semantic sufficiency still requires assessor review.
    """
    if (type(readiness) is not BackendReadiness
            or type(evidence) is not dict or type(source_evidence) is not dict
            or type(readiness.conformance_evidence) is not dict
            or type(maximum_total_bytes) is not int or maximum_total_bytes < 0
            or type(maximum_age_seconds) is not int or maximum_age_seconds < 1):
        return False
    try:
        readiness = BackendReadiness.model_validate(
            readiness.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError, RecursionError):
        return False
    if type(readiness.backend) is not RuntimeBackend:
        return False
    conformance = readiness.conformance_evidence
    if any(type(gate) is not str or type(digest) is not str
           for gate, digest in conformance.items()):
        return False
    if (any(type(gate) is not str for gate in evidence)
            or any(type(gate) is not str for gate in source_evidence)):
        return False
    required = BACKEND_REQUIRED_GATES[readiness.backend]
    expected_gates = set(conformance)
    if (set(evidence) != expected_gates
            or set(source_evidence) != expected_gates
            or not required.issubset(expected_gates)):
        return False
    current_time = _normalized_utc_now(now)
    if current_time is None:
        return False
    total_bytes = 0
    for gate, raw in evidence.items():
        if type(raw) is not bytes:
            return False
        total_bytes += len(raw)
        if total_bytes > maximum_total_bytes:
            return False
        if hashlib.sha256(raw).hexdigest() != readiness.conformance_evidence[gate]:
            return False
        try:
            report = BackendGateEvidence.model_validate_json(raw)
            canonical_report = json.dumps(
                report.model_dump(mode="json"), sort_keys=True,
                separators=(",", ":"), ensure_ascii=True,
                allow_nan=False).encode("utf-8")
        except (ValueError, TypeError):
            return False
        if raw != canonical_report:
            return False
        tested_at = report.tested_at.astimezone(UTC)
        if (report.gate_id != gate
                or report.backend != readiness.backend
                or report.environment_id != readiness.environment_id
                or report.policy_revision != readiness.policy_revision
                or tested_at > current_time
                or (current_time - tested_at).total_seconds() > maximum_age_seconds):
            return False
        source_bytes = source_evidence[gate]
        if type(source_bytes) is not bytes:
            return False
        total_bytes += len(source_bytes)
        if (total_bytes > maximum_total_bytes
                or hashlib.sha256(source_bytes).hexdigest() != report.report_sha256):
            return False
    return True


def _verify_readiness_signer(
    key: TrustedAttestationKey | None,
    *,
    key_id: str,
    signer_id: str,
    signature_text: str,
    payload: bytes,
    issued_at: datetime,
    expires_at: datetime,
    current_time: datetime,
) -> bool:
    key = _validated_trusted_key(key)
    if (key is None or key.key_id != key_id or key.signer_id != signer_id
            or issued_at < key.valid_from.astimezone(UTC)
            or issued_at >= key.expires_at.astimezone(UTC)
            or expires_at > key.expires_at.astimezone(UTC)
            or (key.revoked_at is not None
                and current_time >= key.revoked_at.astimezone(UTC))):
        return False
    try:
        public_key = serialization.load_pem_public_key(key.public_key_pem.encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        signature = base64.b64decode(
            signature_text.encode("ascii")
            + b"=" * (-len(signature_text) % 4),
            altchars=b"-_", validate=True)
        public_key.verify(signature, payload)
    except (ValueError, TypeError, UnicodeEncodeError, InvalidSignature, UnsupportedAlgorithm):
        return False
    return True


def _artifact_key_is_distinct_from_readiness_roles(
    attestation: ArtifactAttestation,
    trusted_artifact_keys: Mapping[str, TrustedAttestationKey],
    readiness: BackendReadiness,
    trusted_readiness_keys: Mapping[str, TrustedAttestationKey],
    trusted_assessor_keys: Mapping[str, TrustedAttestationKey],
) -> bool:
    """Require distinct keys and signer identities across all three roles."""
    key_maps = (trusted_artifact_keys, trusted_readiness_keys, trusted_assessor_keys)
    if any(type(keys) is not dict
           or any(type(key_id) is not str for key_id in keys)
           for keys in key_maps):
        return False
    if (attestation.signer_id == readiness.signer_id
            or attestation.signer_id == readiness.assessor_id):
        return False
    records = (
        trusted_artifact_keys.get(attestation.key_id),
        trusted_readiness_keys.get(readiness.key_id),
        trusted_assessor_keys.get(readiness.assessor_key_id),
    )
    public_keys = []
    try:
        for record in records:
            record = _validated_trusted_key(record)
            if record is None:
                return False
            key = serialization.load_pem_public_key(record.public_key_pem.encode("ascii"))
            if not isinstance(key, Ed25519PublicKey):
                return False
            public_keys.append(key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo))
    except (ValueError, TypeError, UnicodeEncodeError, UnsupportedAlgorithm):
        return False
    return len(set(public_keys)) == len(public_keys)


def verify_backend_readiness(
    readiness: BackendReadiness,
    trusted_keys: Mapping[str, TrustedAttestationKey],
    trusted_assessor_keys: Mapping[str, TrustedAttestationKey],
    *,
    now: datetime | None = None,
    maximum_validity_seconds: int = 24 * 60 * 60,
) -> bool:
    """Verify independently assessed gate evidence and operator readiness."""
    if (type(readiness) is not BackendReadiness
            or type(trusted_keys) is not dict
            or type(trusted_assessor_keys) is not dict
            or any(type(key_id) is not str for key_id in trusted_keys)
            or any(type(key_id) is not str for key_id in trusted_assessor_keys)):
        return False
    try:
        readiness = BackendReadiness.model_validate(
            readiness.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError, RecursionError):
        return False
    current_time = _normalized_utc_now(now)
    if current_time is None:
        return False
    issued_at = readiness.issued_at.astimezone(UTC)
    expires_at = readiness.expires_at.astimezone(UTC)
    if (type(maximum_validity_seconds) is not int or maximum_validity_seconds < 1
            or (expires_at - issued_at).total_seconds() > maximum_validity_seconds
            or issued_at > current_time or current_time >= expires_at
            or readiness.key_id == readiness.assessor_key_id
            or readiness.signer_id == readiness.assessor_id):
        return False
    operator_key = _validated_trusted_key(trusted_keys.get(readiness.key_id))
    assessor_key = _validated_trusted_key(
        trusted_assessor_keys.get(readiness.assessor_key_id))
    if (operator_key is None or assessor_key is None
            or operator_key.key_id != readiness.key_id
            or operator_key.signer_id != readiness.signer_id
            or assessor_key.key_id != readiness.assessor_key_id
            or assessor_key.signer_id != readiness.assessor_id):
        return False
    try:
        operator_public = serialization.load_pem_public_key(
            operator_key.public_key_pem.encode("ascii"))
        assessor_public = serialization.load_pem_public_key(
            assessor_key.public_key_pem.encode("ascii"))
        if (not isinstance(operator_public, Ed25519PublicKey)
                or not isinstance(assessor_public, Ed25519PublicKey)
                or operator_public.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)
                == assessor_public.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo)):
            return False
    except (ValueError, TypeError, UnicodeEncodeError, UnsupportedAlgorithm):
        return False
    operator_ok = _verify_readiness_signer(
        operator_key, key_id=readiness.key_id,
        signer_id=readiness.signer_id, signature_text=readiness.signature,
        payload=backend_readiness_signing_payload(readiness),
        issued_at=issued_at, expires_at=expires_at, current_time=current_time)
    assessor_ok = _verify_readiness_signer(
        assessor_key,
        key_id=readiness.assessor_key_id, signer_id=readiness.assessor_id,
        signature_text=readiness.assessor_signature,
        payload=backend_conformance_signing_payload(readiness),
        issued_at=issued_at, expires_at=expires_at, current_time=current_time)
    return operator_ok and assessor_ok


class AdmissionRequest(StrictContract):
    run_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    backend: RuntimeBackend
    backend_environment_id: str = Field(min_length=1, max_length=160)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    input_bytes: int = Field(ge=0, le=1_048_576, strict=True)
    deadline_seconds: int = Field(ge=1, le=3600, strict=True)

    @field_validator(
        "run_id", "tenant_id", "agent_id", "version", "backend_environment_id",
        "sha256", mode="before",
    )
    @classmethod
    def _admission_text_fields_are_builtin(cls, value: object) -> object:
        if type(value) is not str:
            raise ValueError("admission request text fields must be built-in strings")
        return value


class AdmissionDecision(StrictContract):
    admitted: bool = Field(strict=True)
    reason: Literal[
        "admitted", "backend_not_provisioned", "backend_readiness_stale",
        "backend_not_conformant", "artifact_not_approved", "artifact_revoked",
        "artifact_state_invalid", "artifact_signature_invalid",
        "artifact_mismatch", "agent_version_mismatch",
        "resource_limit_exceeded",
    ]
    backend: RuntimeBackend
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_revision: str

    @field_validator("reason", "artifact_sha256", "policy_revision", mode="before")
    @classmethod
    def _decision_text_fields_are_builtin(cls, value: object) -> object:
        if type(value) is not str:
            raise ValueError("admission decision text fields must be built-in strings")
        return value

    @model_validator(mode="after")
    def _admission_reason_matches_state(self) -> "AdmissionDecision":
        if self.admitted != (self.reason == "admitted"):
            raise ValueError("admission state and reason must be consistent")
        return self


class RuntimeAuditEvent(StrictContract):
    event_id: str = Field(min_length=1, max_length=128)
    occurred_at: datetime
    event_type: Literal[
        "admission_denied", "run_queued", "run_started", "run_completed",
        "run_failed", "run_cancelled", "artifact_revoked", "sandbox_cleanup",
    ]
    run_id: str | None = Field(default=None, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=128)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$", max_length=32)
    backend: RuntimeBackend
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_revision: str = Field(min_length=1, max_length=80)
    reason_code: str = Field(min_length=1, max_length=80)

    @field_validator(
        "event_id", "event_type", "run_id", "tenant_id", "agent_id", "version",
        "artifact_sha256", "policy_revision", "reason_code", mode="before",
    )
    @classmethod
    def _text_fields_are_builtin(cls, value: object) -> object:
        if value is None:
            return None
        if type(value) is not str:
            raise ValueError("audit event text fields must be built-in strings")
        return value

    @field_validator("occurred_at", mode="before")
    @classmethod
    def _occurred_at_input_explicit(cls, value: object) -> object:
        return _explicit_datetime_input(value)

    @field_validator("occurred_at")
    @classmethod
    def _occurred_at_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("audit timestamp must include a timezone")
        return value

    @field_validator("artifact_sha256")
    @classmethod
    def _lowercase_digest(cls, value: str) -> str:
        if value != value.lower():
            raise ValueError("digest must be lowercase hexadecimal")
        return value


def decide_admission(
    request: AdmissionRequest,
    *,
    attestation: ArtifactAttestation | None,
    artifact_bytes: bytes | None,
    trusted_keys: Mapping[str, TrustedAttestationKey],
    trusted_readiness_keys: Mapping[str, TrustedAttestationKey],
    trusted_conformance_keys: Mapping[str, TrustedAttestationKey],
    backend_evidence: Mapping[str, bytes] | None,
    backend_source_evidence: Mapping[str, bytes] | None,
    current_readiness_generation: int | None,
    review_approved: bool,
    artifact_revoked: bool,
    backend_readiness: BackendReadiness | None,
    maximum_input_bytes: int = 1_048_576,
    maximum_deadline_seconds: int = 3600,
    maximum_artifact_bytes: int = 50 * 1024 * 1024,
    maximum_attestation_age_seconds: int = 90 * 24 * 60 * 60,
) -> AdmissionDecision:
    """Evaluate explicit pinning and readiness; never choose another backend.

    The review-state and readiness arguments must come from trusted,
    independently verified control-plane sources. Artifact attestations and
    backend readiness and independent conformance assessment use distinct
    trusted-key sets, preventing artifact reviewers or readiness operators
    from asserting their own isolation evidence. The
    attestation signature is verified against operator-supplied keys, and artifact bytes
    must match its signed digest. This does not retrieve or persist artifact
    bytes, launch a sandbox, or prove a backend is secure.
    """
    if type(request) is not AdmissionRequest:
        raise ValueError("invalid admission request contract")
    try:
        request = AdmissionRequest.model_validate(request.model_dump(mode="python"))
    except (AttributeError, TypeError, ValueError, ValidationError, RecursionError) as exc:
        raise ValueError("invalid admission request contract") from exc

    readiness = backend_readiness
    if readiness is not None:
        if type(readiness) is not BackendReadiness:
            readiness = None
        else:
            try:
                readiness = BackendReadiness.model_validate(
                    readiness.model_dump(mode="python"))
            except (AttributeError, TypeError, ValueError, ValidationError,
                    RecursionError):
                readiness = None
    policy_revision = readiness.policy_revision if readiness else "unavailable"
    base = {"backend": request.backend, "artifact_sha256": request.sha256,
            "policy_revision": policy_revision}

    def deny(reason: str) -> AdmissionDecision:
        return AdmissionDecision(admitted=False, reason=reason, **base)

    if (readiness is None or readiness.backend != request.backend
            or readiness.environment_id != request.backend_environment_id
            or not readiness.enabled):
        return deny("backend_not_provisioned")
    if type(artifact_revoked) is not bool or type(review_approved) is not bool:
        return deny("artifact_state_invalid")
    if artifact_revoked:
        return deny("artifact_revoked")
    if attestation is None or not review_approved:
        return deny("artifact_not_approved")
    if not verify_attestation_signature(
            attestation, trusted_keys,
            maximum_age_seconds=maximum_attestation_age_seconds):
        return deny("artifact_signature_invalid")
    if not verify_backend_readiness(
            readiness, trusted_readiness_keys, trusted_conformance_keys):
        return deny("backend_not_provisioned")
    if not _artifact_key_is_distinct_from_readiness_roles(
            attestation, trusted_keys, readiness,
            trusted_readiness_keys, trusted_conformance_keys):
        return deny("artifact_signature_invalid")
    if (type(current_readiness_generation) is not int
            or current_readiness_generation != readiness.generation):
        return deny("backend_readiness_stale")
    if not verify_backend_evidence(
            readiness, backend_evidence, backend_source_evidence):
        return deny("backend_not_conformant")
    if (attestation.backend != request.backend
            or attestation.sha256 != request.sha256):
        return deny("artifact_mismatch")
    if attestation.agent_id != request.agent_id or attestation.version != request.version:
        return deny("agent_version_mismatch")
    if not verify_artifact_bytes(
            attestation, artifact_bytes, maximum_bytes=maximum_artifact_bytes):
        return deny("artifact_mismatch")
    if (type(maximum_input_bytes) is not int or maximum_input_bytes < 0
            or type(maximum_deadline_seconds) is not int or maximum_deadline_seconds < 1
            or request.input_bytes > maximum_input_bytes
            or request.deadline_seconds > maximum_deadline_seconds):
        return deny("resource_limit_exceeded")
    return AdmissionDecision(admitted=True, reason="admitted", **base)
