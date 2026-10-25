"""Pure contract tests: no sandbox or publisher code is provisioned or run."""
import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta, tzinfo
from unittest.mock import patch

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from src.agent_marketplace.runtime_contract import (
    BACKEND_REQUIRED_GATES,
    AdmissionDecision,
    AdmissionRequest,
    ArtifactAttestation,
    BackendGateEvidence,
    BackendReadiness,
    RuntimeAuditEvent,
    RuntimeBackend,
    TrustedAttestationKey,
    attestation_signing_payload,
    backend_conformance_signing_payload,
    backend_readiness_signing_payload,
    decide_admission,
    verify_artifact_bytes,
    verify_attestation_signature,
    verify_backend_evidence,
    verify_backend_readiness,
)

ARTIFACT_BYTES = b"minimal inert wasm artifact fixture"
DIGEST = hashlib.sha256(ARTIFACT_BYTES).hexdigest()
NOW = datetime.now(UTC)
_PRIVATE_KEY = Ed25519PrivateKey.generate()
_PUBLIC_KEY_PEM = _PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo)
def _trusted_key(public_pem=_PUBLIC_KEY_PEM, **changes):
    data = {
        "key_id": "review-key-1", "signer_id": "review-service",
        "public_key_pem": public_pem.decode("ascii"),
        "valid_from": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(days=1),
    }
    data.update(changes)
    return TrustedAttestationKey(**data)


_TRUSTED_KEYS = {"review-key-1": _trusted_key()}
_READINESS_PRIVATE_KEY = Ed25519PrivateKey.generate()
_READINESS_PUBLIC_KEY_PEM = _READINESS_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo)
_READINESS_KEY = TrustedAttestationKey(
    key_id="readiness-key-1", signer_id="runtime-operator",
    public_key_pem=_READINESS_PUBLIC_KEY_PEM.decode("ascii"),
    valid_from=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
_READINESS_KEYS = {"readiness-key-1": _READINESS_KEY}
_ASSESSOR_PRIVATE_KEY = Ed25519PrivateKey.generate()
_ASSESSOR_PUBLIC_KEY_PEM = _ASSESSOR_PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo)
_ASSESSOR_KEY = TrustedAttestationKey(
    key_id="assessor-key-1", signer_id="independent-assessor",
    public_key_pem=_ASSESSOR_PUBLIC_KEY_PEM.decode("ascii"),
    valid_from=NOW - timedelta(days=1), expires_at=NOW + timedelta(days=1))
_ASSESSOR_KEYS = {"assessor-key-1": _ASSESSOR_KEY}


def _request(**changes):
    data = {
        "run_id": "run-1", "tenant_id": "tenant-1", "agent_id": "agent-1",
        "version": "1.2.3", "backend": RuntimeBackend.WASM_WASI,
        "backend_environment_id": "pool-test-a",
        "sha256": DIGEST, "input_bytes": 128, "deadline_seconds": 30,
    }
    data.update(changes)
    return AdmissionRequest(**data)


def _attestation(**changes):
    data = {
        "agent_id": "agent-1", "version": "1.2.3",
        "backend": RuntimeBackend.WASM_WASI, "sha256": DIGEST,
        "provenance_id": "prov-1", "signer_id": "review-service",
        "key_id": "review-key-1", "signature_algorithm": "ed25519",
        "signature": "pending", "created_at": NOW,
    }
    data.update(changes)
    attestation = ArtifactAttestation(**data)
    if "signature" not in changes:
        signature = base64.urlsafe_b64encode(
            _PRIVATE_KEY.sign(attestation_signing_payload(attestation))
        ).decode().rstrip("=")
        attestation = attestation.model_copy(update={"signature": signature})
    return attestation


def _source_evidence_for(backend):
    return {
        gate: f"source-report:{backend.value}:{gate}".encode()
        for gate in BACKEND_REQUIRED_GATES[backend]
    }


def _evidence_for(backend, *, environment_id="pool-test-a",
                  policy_revision="policy-v1", tested_at=NOW,
                  source_evidence=None):
    source_evidence = source_evidence or _source_evidence_for(backend)
    reports = {}
    for gate in BACKEND_REQUIRED_GATES[backend]:
        report = BackendGateEvidence(
            gate_id=gate, backend=backend, environment_id=environment_id,
            policy_revision=policy_revision, result="passed", tested_at=tested_at,
            test_run_id=f"conformance-{backend.value}-{gate}",
            report_sha256=hashlib.sha256(source_evidence[gate]).hexdigest())
        reports[gate] = json.dumps(
            report.model_dump(mode="json"), sort_keys=True,
            separators=(",", ":")).encode()
    return reports


def _ready(**changes):
    assessor_private_key = changes.pop(
        "assessor_private_key", _ASSESSOR_PRIVATE_KEY)
    backend = changes.get("backend", RuntimeBackend.WASM_WASI)
    environment_id = changes.get("environment_id", "pool-test-a")
    policy_revision = changes.get("policy_revision", "policy-v1")
    evidence = changes.pop("evidence_override", None) or _evidence_for(
        backend, environment_id=environment_id, policy_revision=policy_revision)
    data = {
        "backend": backend,
        "environment_id": "pool-test-a",
        "generation": 1,
        "enabled": True,
        "conformance_evidence": {
            gate: hashlib.sha256(raw).hexdigest()
            for gate, raw in evidence.items()
        },
        "policy_revision": "policy-v1",
        "issued_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
        "signer_id": "runtime-operator",
        "key_id": "readiness-key-1",
        "assessor_id": "independent-assessor",
        "assessor_key_id": "assessor-key-1",
        "assessor_signature": "pending-assessor",
        "signature": "pending-operator",
    }
    data.update(changes)
    readiness = BackendReadiness(**data)
    assessor_signature = base64.urlsafe_b64encode(
        assessor_private_key.sign(backend_conformance_signing_payload(readiness))
    ).decode().rstrip("=")
    readiness = readiness.model_copy(update={"assessor_signature": assessor_signature})
    operator_signature = base64.urlsafe_b64encode(
        _READINESS_PRIVATE_KEY.sign(backend_readiness_signing_payload(readiness))
    ).decode().rstrip("=")
    return readiness.model_copy(update={"signature": operator_signature})


_DEFAULT = object()


def _decide(request=None, *, attestation=_DEFAULT, approved=True,
            readiness=_DEFAULT, trusted_keys=_TRUSTED_KEYS,
            readiness_keys=_READINESS_KEYS,
            conformance_keys=_ASSESSOR_KEYS,
            backend_evidence=_DEFAULT,
            backend_source_evidence=_DEFAULT,
            current_readiness_generation=1,
            artifact_bytes=ARTIFACT_BYTES, revoked=False,
            maximum_input_bytes=1_048_576, maximum_deadline_seconds=3600):
    if attestation is _DEFAULT:
        attestation = _attestation()
    if readiness is _DEFAULT:
        readiness = _ready()
    if backend_evidence is _DEFAULT:
        backend_evidence = (
            _evidence_for(readiness.backend) if readiness is not None else None)
    if backend_source_evidence is _DEFAULT:
        backend_source_evidence = (
            _source_evidence_for(readiness.backend) if readiness is not None else None)
    return decide_admission(
        request or _request(), attestation=attestation,
        artifact_bytes=artifact_bytes, trusted_keys=trusted_keys,
        trusted_readiness_keys=readiness_keys,
        trusted_conformance_keys=conformance_keys,
        backend_evidence=backend_evidence,
        backend_source_evidence=backend_source_evidence,
        current_readiness_generation=current_readiness_generation,
        review_approved=approved, artifact_revoked=revoked,
        backend_readiness=readiness, maximum_input_bytes=maximum_input_bytes,
        maximum_deadline_seconds=maximum_deadline_seconds)


def test_backend_required_gate_contracts_cover_isolation_controls():
    assert BACKEND_REQUIRED_GATES[RuntimeBackend.WASM_WASI] == frozenset({
        "runtime_version_pinned", "component_abi_pinned", "host_imports_allowlisted",
        "filesystem_denied", "process_access_denied", "clock_randomness_restricted",
        "fuel_memory_and_io_bounded", "network_denied", "cancellation_verified",
        "cross_run_cleanup_verified",
    })
    assert BACKEND_REQUIRED_GATES[RuntimeBackend.SANDBOXED_KUBERNETES] == frozenset({
        "dedicated_pool", "sandbox_runtime_verified", "host_access_denied",
        "nonroot_readonly_pod", "capabilities_seccomp_restricted",
        "cpu_memory_pid_disk_quotas", "network_policy_enforced", "metadata_blocked",
        "cancellation_verified", "cross_run_cleanup_verified",
    })
    assert BACKEND_REQUIRED_GATES[RuntimeBackend.MICROVM] == frozenset({
        "dedicated_kvm_hosts", "vmm_and_guest_pinned", "fresh_vm_per_run",
        "no_shared_writable_storage", "minimal_readonly_guest", "network_denied",
        "resource_quotas_enforced", "vmm_api_vsock_restricted",
        "cancellation_verified", "cross_run_cleanup_verified",
    })


def test_artifact_review_key_must_differ_from_readiness_operator_and_assessor():
    for shared_private_key, shared_signer in (
            (_READINESS_PRIVATE_KEY, "runtime-operator"),
            (_ASSESSOR_PRIVATE_KEY, "independent-assessor")):
        public_pem = shared_private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        artifact_key = TrustedAttestationKey(
            key_id="review-key-1", signer_id="review-service",
            public_key_pem=public_pem.decode("ascii"),
            valid_from=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1))
        unsigned = _attestation(signature="pending")
        signature = base64.urlsafe_b64encode(
            shared_private_key.sign(attestation_signing_payload(unsigned))
        ).decode().rstrip("=")
        signed = unsigned.model_copy(update={"signature": signature})
        result = _decide(attestation=signed, trusted_keys={"review-key-1": artifact_key})
        assert not result.admitted
        assert result.reason == "artifact_signature_invalid"


def test_artifact_reviewer_identity_must_differ_from_readiness_roles():
    for shared_identity in ("runtime-operator", "independent-assessor"):
        artifact_key = TrustedAttestationKey(
            key_id="review-key-1", signer_id=shared_identity,
            public_key_pem=_PUBLIC_KEY_PEM.decode("ascii"),
            valid_from=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=1))
        unsigned = _attestation(signature="pending", signer_id=shared_identity)
        signature = base64.urlsafe_b64encode(
            _PRIVATE_KEY.sign(attestation_signing_payload(unsigned))
        ).decode().rstrip("=")
        signed = unsigned.model_copy(update={"signature": signature})
        result = _decide(attestation=signed, trusted_keys={"review-key-1": artifact_key})
        assert not result.admitted
        assert result.reason == "artifact_signature_invalid"


def test_backend_readiness_requires_cryptographically_distinct_signers():
    readiness = _ready(assessor_private_key=_READINESS_PRIVATE_KEY)
    same_key_as_assessor = TrustedAttestationKey(
        key_id="assessor-key-1", signer_id="independent-assessor",
        public_key_pem=_READINESS_PUBLIC_KEY_PEM.decode("ascii"),
        valid_from=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=1))
    assert not verify_backend_readiness(
        readiness, _READINESS_KEYS,
        {"assessor-key-1": same_key_as_assessor}, now=NOW)


def test_backend_readiness_evidence_is_backend_specific_and_signed():
    for backend, required_gates in BACKEND_REQUIRED_GATES.items():
        readiness = _ready(backend=backend)
        evidence = _evidence_for(backend)
        assert set(readiness.conformance_evidence) == required_gates
        assert verify_backend_readiness(
            readiness, _READINESS_KEYS, _ASSESSOR_KEYS, now=NOW)
        oversized_operator_keys = {
            f"unrelated-{index}": _READINESS_KEYS["readiness-key-1"]
            for index in range(257)
        }
        assert not verify_backend_readiness(
            readiness, oversized_operator_keys, _ASSESSOR_KEYS, now=NOW)
        assert not verify_backend_readiness(
            readiness, _READINESS_KEYS, {"x" * 161: _ASSESSOR_KEYS["assessor-key-1"]},
            now=NOW)

        class TrustedKeyMap(dict):
            pass

        assert not verify_backend_readiness(
            readiness, TrustedKeyMap(_READINESS_KEYS), _ASSESSOR_KEYS, now=NOW)
        assert not verify_backend_readiness(
            readiness, _READINESS_KEYS, TrustedKeyMap(_ASSESSOR_KEYS), now=NOW)
        mutated_operator_key = _READINESS_KEYS["readiness-key-1"].model_copy(
            update={"expires_at": NOW})
        assert not verify_backend_readiness(
            readiness, {"readiness-key-1": mutated_operator_key},
            _ASSESSOR_KEYS, now=NOW)
        assert not verify_backend_readiness(
            readiness, _READINESS_KEYS, _ASSESSOR_KEYS, now=NOW,
            maximum_validity_seconds=60)
        source_evidence = _source_evidence_for(backend)
        assert verify_backend_evidence(
            readiness, evidence, source_evidence, now=NOW)

        class EvidenceDict(dict):
            pass

        assert not verify_backend_evidence(
            readiness, EvidenceDict(evidence), source_evidence, now=NOW)
        assert not verify_backend_evidence(
            readiness, evidence, EvidenceDict(source_evidence), now=NOW)

        class HostileBytes(bytes):
            def __len__(self):
                raise RuntimeError("hostile length")

        first_gate = next(iter(evidence))
        hostile_report = dict(evidence)
        hostile_report[first_gate] = HostileBytes(hostile_report[first_gate])
        assert not verify_backend_evidence(
            readiness, hostile_report, source_evidence, now=NOW)
        hostile_source = dict(source_evidence)
        hostile_source[first_gate] = HostileBytes(hostile_source[first_gate])
        assert not verify_backend_evidence(
            readiness, evidence, hostile_source, now=NOW)

        tampered = dict(evidence)
        first_gate = next(iter(tampered))
        tampered[first_gate] += b"tampered"
        assert not verify_backend_evidence(
            readiness, tampered, _source_evidence_for(backend), now=NOW)
        assert not verify_backend_evidence(readiness, {}, {}, now=NOW)
        assert not verify_backend_evidence(
            readiness, evidence, _source_evidence_for(backend), now=NOW,
            maximum_total_bytes=1)
        altered_source = _source_evidence_for(backend)
        altered_source[first_gate] += b"tampered"
        assert not verify_backend_evidence(
            readiness, evidence, altered_source, now=NOW)

    with pytest.raises(ValidationError, match="unknown backend gates"):
        _ready(conformance_evidence={
            "microvm_vm_per_run": hashlib.sha256(b"vm").hexdigest()})


def test_readiness_conformance_evidence_rejects_non_builtin_containers_and_strings():
    class EvidenceDict(dict):
        pass

    class HostileText(str):
        pass

    base = _ready().model_dump(mode="python")
    with pytest.raises(ValidationError, match="built-in dictionary"):
        BackendReadiness(**{
            **base, "conformance_evidence": EvidenceDict(base["conformance_evidence"]),
        })
    hostile_key = HostileText(next(iter(base["conformance_evidence"])))
    with pytest.raises(ValidationError, match="built-in strings"):
        BackendReadiness(**{
            **base, "conformance_evidence": {
                hostile_key: next(iter(base["conformance_evidence"].values())),
            },
        })
    hostile_digest = HostileText(next(iter(base["conformance_evidence"].values())))
    with pytest.raises(ValidationError, match="built-in strings"):
        BackendReadiness(**{
            **base, "conformance_evidence": {
                next(iter(base["conformance_evidence"])): hostile_digest,
            },
        })


@pytest.mark.parametrize("field", [
    "environment_id", "policy_revision", "signer_id", "key_id", "assessor_id",
    "assessor_key_id", "assessor_signature", "signature_algorithm", "signature",
])
def test_backend_readiness_rejects_text_subclasses(field):
    class HostileText(str):
        pass

    data = _ready().model_dump(mode="python")
    data[field] = HostileText(data[field])
    with pytest.raises(ValidationError, match="readiness text fields must be built-in strings"):
        BackendReadiness(**data)


def test_admission_requires_all_pins_review_and_backend_gates():
    assert _decide(attestation=_attestation(), readiness=_ready()).admitted
    assert _decide(approved=False).reason == "artifact_not_approved"
    assert _decide(approved=False, revoked=True).reason == "artifact_revoked"
    assert _decide(approved="false").reason == "artifact_state_invalid"
    assert _decide(revoked="false").reason == "artifact_state_invalid"
    assert _decide(attestation=None).reason == "artifact_not_approved"
    assert _decide(attestation=_attestation(signature="bad")).reason == "artifact_signature_invalid"
    assert _decide(trusted_keys={}).reason == "artifact_signature_invalid"
    assert _decide(artifact_bytes=None).reason == "artifact_mismatch"
    assert _decide(artifact_bytes=ARTIFACT_BYTES + b"tampered").reason == "artifact_mismatch"
    assert _decide(readiness=None).reason == "backend_not_provisioned"
    assert _decide(readiness=_ready(enabled=False)).reason == "backend_not_provisioned"
    assert _decide(readiness=_ready(conformance_evidence={})).reason == "backend_not_conformant"
    assert _decide(backend_evidence=None).reason == "backend_not_conformant"
    assert _decide(backend_source_evidence=None).reason == "backend_not_conformant"
    altered_evidence = _evidence_for(RuntimeBackend.WASM_WASI)
    first_gate = next(iter(altered_evidence))
    altered_evidence[first_gate] += b"tampered"
    assert _decide(backend_evidence=altered_evidence).reason == "backend_not_conformant"
    wrong_pool_evidence = _evidence_for(
        RuntimeBackend.WASM_WASI, environment_id="pool-other")
    wrong_pool_readiness = _ready(evidence_override=wrong_pool_evidence)
    assert _decide(
        readiness=wrong_pool_readiness,
        backend_evidence=wrong_pool_evidence).reason == "backend_not_conformant"
    noncanonical_evidence = _evidence_for(RuntimeBackend.WASM_WASI)
    first_gate = next(iter(noncanonical_evidence))
    noncanonical_evidence[first_gate] = b" " + noncanonical_evidence[first_gate]
    noncanonical_readiness = _ready(evidence_override=noncanonical_evidence)
    assert not verify_backend_evidence(
        noncanonical_readiness, noncanonical_evidence,
        _source_evidence_for(RuntimeBackend.WASM_WASI), now=NOW)
    stale_evidence = _evidence_for(
        RuntimeBackend.WASM_WASI, tested_at=NOW - timedelta(days=2))
    stale_readiness = _ready(evidence_override=stale_evidence)
    assert not verify_backend_evidence(
        stale_readiness, stale_evidence,
        _source_evidence_for(RuntimeBackend.WASM_WASI), now=NOW)
    future_evidence = _evidence_for(
        RuntimeBackend.WASM_WASI, tested_at=NOW + timedelta(minutes=1))
    future_readiness = _ready(evidence_override=future_evidence)
    assert not verify_backend_evidence(
        future_readiness, future_evidence,
        _source_evidence_for(RuntimeBackend.WASM_WASI), now=NOW)
    assert _decide(readiness=_ready().model_copy(
        update={"signature": "invalid"})).reason == "backend_not_provisioned"
    # Artifact-review trust alone must never assert backend isolation readiness.
    assert _decide(readiness_keys={}).reason == "backend_not_provisioned"
    assert _decide(conformance_keys={}).reason == "backend_not_provisioned"
    assert _decide(readiness=_ready().model_copy(
        update={"assessor_signature": "invalid"})).reason == "backend_not_provisioned"
    assert _decide(readiness=_ready().model_copy(
        update={"enabled": False})).reason == "backend_not_provisioned"
    assert _decide(current_readiness_generation=None).reason == "backend_readiness_stale"
    assert _decide(current_readiness_generation=2).reason == "backend_readiness_stale"
    # bool is an int subclass in Python; it must not satisfy generation binding.
    assert _decide(current_readiness_generation=True).reason == "backend_readiness_stale"
    assert _decide(request=_request(backend_environment_id="pool-prod-b")).reason \
        == "backend_not_provisioned"
    assert _decide(readiness=_ready(
        issued_at=NOW - timedelta(hours=2),
        expires_at=NOW - timedelta(hours=1))).reason == "backend_not_provisioned"
    assert _decide(readiness=_ready(
        issued_at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1))).reason == "backend_not_provisioned"


def test_admission_rejects_backend_digest_and_version_mismatch_without_fallback():
    assert _decide(attestation=_attestation(sha256="b" * 64)).reason == "artifact_mismatch"
    assert _decide(attestation=_attestation(
        backend=RuntimeBackend.MICROVM)).reason == "artifact_mismatch"
    assert _decide(request=_request(version="2.0.0")).reason == "agent_version_mismatch"
    # Availability of a different class never substitutes for the pinned class.
    other_backend_ready = _ready(backend=RuntimeBackend.MICROVM)
    assert _decide(readiness=other_backend_ready).reason == "backend_not_provisioned"


@pytest.mark.parametrize("field", [
    "run_id", "tenant_id", "agent_id", "version", "backend_environment_id", "sha256",
])
def test_admission_request_rejects_string_subclasses(field):
    class HostileText(str):
        pass

    data = _request().model_dump(mode="python")
    data[field] = HostileText(data[field])
    with pytest.raises(ValidationError, match="admission request text fields must be built-in strings"):
        AdmissionRequest(**data)


def test_admission_revalidates_request_and_readiness_contracts():
    invalid_request = _request().model_copy(update={"input_bytes": True})
    with pytest.raises(ValueError, match="invalid admission request contract"):
        _decide(request=invalid_request)

    class AdmissionRequestSubclass(AdmissionRequest):
        pass

    subclass_request = AdmissionRequestSubclass.model_validate(
        _request().model_dump())
    with pytest.raises(ValueError, match="invalid admission request contract"):
        _decide(request=subclass_request)

    invalid_readiness = _ready().model_copy(update={"generation": True})
    assert _decide(readiness=invalid_readiness).reason == "backend_not_provisioned"


def test_admission_enforces_resource_bounds():
    request = _request(input_bytes=512, deadline_seconds=30)
    result = decide_admission(
        request, attestation=_attestation(), artifact_bytes=ARTIFACT_BYTES,
        trusted_keys=_TRUSTED_KEYS, trusted_readiness_keys=_READINESS_KEYS,
        trusted_conformance_keys=_ASSESSOR_KEYS,
        backend_evidence=_evidence_for(RuntimeBackend.WASM_WASI),
        backend_source_evidence=_source_evidence_for(RuntimeBackend.WASM_WASI),
        current_readiness_generation=1,
        review_approved=True,
        artifact_revoked=False, backend_readiness=_ready(), maximum_input_bytes=256,
        maximum_deadline_seconds=20)
    assert result.reason == "resource_limit_exceeded"

    with pytest.raises(ValidationError):
        _request(input_bytes=1_048_577)
    with pytest.raises(ValidationError):
        _request(deadline_seconds=3601)


def test_contract_backend_fields_reject_string_subclasses():
    class HostileText(str):
        pass

    contracts = [
        _attestation(), _ready(), _request(),
        AdmissionDecision(
            admitted=True, reason="admitted", backend=RuntimeBackend.WASM_WASI,
            artifact_sha256=DIGEST, policy_revision="policy-v1"),
        BackendGateEvidence(
            gate_id="runtime_version_pinned", backend=RuntimeBackend.WASM_WASI,
            environment_id="pool-test-a", policy_revision="policy-v1",
            result="passed", tested_at=NOW, test_run_id="test-1",
            report_sha256=DIGEST),
        RuntimeAuditEvent(
            event_id="evt-backend", occurred_at=NOW,
            event_type="admission_denied", tenant_id="tenant-1",
            agent_id="agent-1", version="1.0.0",
            backend=RuntimeBackend.WASM_WASI, artifact_sha256=DIGEST,
            policy_revision="policy-v1", reason_code="denied"),
    ]
    for contract in contracts:
        data = contract.model_dump(mode="python")
        data["backend"] = HostileText(contract.backend.value)
        with pytest.raises(ValidationError, match="RuntimeBackend or built-in string"):
            type(contract)(**data)


def test_trusted_key_rejects_string_subclasses():
    class HostileText(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("trusted-key string subclass callbacks must not run")

    data = _trusted_key().model_dump()
    with pytest.raises(ValidationError, match="built-in strings"):
        TrustedAttestationKey(**{
            **data, "public_key_pem": HostileText(data["public_key_pem"]),
        })


def test_backend_gate_evidence_rejects_string_subclasses():
    class HostileText(str):
        def __eq__(self, other):
            raise AssertionError("gate-evidence string subclass equality must not run")

    valid = BackendGateEvidence(
        gate_id="runtime_version_pinned", backend=RuntimeBackend.WASM_WASI,
        environment_id="pool-test-a", policy_revision="policy-v1",
        result="passed", tested_at=NOW, test_run_id="test-1",
        report_sha256="a" * 64)
    with pytest.raises(ValidationError, match="built-in strings"):
        BackendGateEvidence(**{
            **valid.model_dump(), "result": HostileText("passed"),
        })


def test_artifact_attestation_rejects_string_subclasses():
    class HostileText(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("attestation string subclass callbacks must not run")

    data = _attestation().model_dump()
    with pytest.raises(ValidationError, match="built-in strings"):
        ArtifactAttestation(**{
            **data, "signature": HostileText(data["signature"]),
        })


def test_artifact_attestation_requires_timezone_aware_creation_time():
    with pytest.raises(ValidationError, match="timezone"):
        _attestation(created_at=NOW.replace(tzinfo=None))


def test_contract_timestamps_reject_implicit_epoch_coercion():
    with pytest.raises(ValidationError, match="timestamp"):
        _attestation(created_at=1_800_000_000)
    with pytest.raises(ValidationError, match="timestamp"):
        _attestation(created_at="1800000000")
    with pytest.raises(ValidationError, match="timestamp"):
        _trusted_key(valid_from=1_800_000_000)
    with pytest.raises(ValidationError, match="timestamp"):
        _ready(issued_at=1_800_000_000)
    with pytest.raises(ValidationError, match="timestamp"):
        BackendGateEvidence(
            gate_id="runtime_version_pinned", backend=RuntimeBackend.WASM_WASI,
            environment_id="pool-test-a", policy_revision="policy-v1",
            result="passed", tested_at=1_800_000_000, test_run_id="test-1",
            report_sha256="a" * 64)
    with pytest.raises(ValidationError, match="timestamp"):
        RuntimeAuditEvent(
            event_id="evt-time", occurred_at=1_800_000_000,
            event_type="admission_denied", tenant_id="tenant-1",
            agent_id="agent-1", version="1.0.0",
            backend=RuntimeBackend.WASM_WASI, artifact_sha256=DIGEST,
            policy_revision="policy-v1", reason_code="denied")


def test_verifiers_fail_closed_on_invalid_now_argument_types():
    signed = _attestation()
    readiness = _ready()
    assert not verify_attestation_signature(signed, _TRUSTED_KEYS, now=True)
    assert not verify_backend_readiness(
        readiness, _READINESS_KEYS, _ASSESSOR_KEYS, now=True)

    class ReadinessSubclass(BackendReadiness):
        pass

    subclass_readiness = ReadinessSubclass.model_validate(readiness.model_dump())
    assert not verify_backend_readiness(
        subclass_readiness, _READINESS_KEYS, _ASSESSOR_KEYS, now=NOW)
    bypassed_validation = readiness.model_copy(update={"generation": True})
    assert not verify_backend_readiness(
        bypassed_validation, _READINESS_KEYS, _ASSESSOR_KEYS, now=NOW)
    assert not verify_backend_evidence(
        bypassed_validation, _evidence_for(readiness.backend),
        _source_evidence_for(readiness.backend), now=NOW)
    assert not verify_backend_evidence(
        subclass_readiness, _evidence_for(readiness.backend),
        _source_evidence_for(readiness.backend), now=NOW)
    assert not verify_backend_evidence(
        readiness, _evidence_for(readiness.backend),
        _source_evidence_for(readiness.backend), now=True)

    class HostileDateTime(datetime):
        def utcoffset(self):
            raise AssertionError("datetime subclass callbacks must not run")

    hostile_now = HostileDateTime(
        NOW.year, NOW.month, NOW.day, NOW.hour, NOW.minute, NOW.second,
        NOW.microsecond, tzinfo=UTC)
    assert not verify_attestation_signature(
        signed, _TRUSTED_KEYS, now=hostile_now)
    assert not verify_backend_readiness(
        readiness, _READINESS_KEYS, _ASSESSOR_KEYS, now=hostile_now)

    class HostileTimezone(tzinfo):
        def utcoffset(self, dt):
            raise AssertionError("caller-defined timezone callbacks must not run")

    hostile_timezone_now = NOW.replace(tzinfo=HostileTimezone())
    assert not verify_attestation_signature(
        signed, _TRUSTED_KEYS, now=hostile_timezone_now)
    with pytest.raises(ValidationError, match="standard-library timezone"):
        _attestation(created_at=hostile_timezone_now)


def test_attestation_signature_verifies_claim_and_fails_closed_on_tampering():
    private_key = Ed25519PrivateKey.generate()
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    unsigned = _attestation(signature="pending")
    signature = base64.urlsafe_b64encode(
        private_key.sign(attestation_signing_payload(unsigned))).decode().rstrip("=")
    signed = unsigned.model_copy(update={"signature": signature})

    test_keys = {"review-key-1": _trusted_key(public_pem)}
    assert verify_attestation_signature(signed, test_keys, now=NOW)
    with patch(
        "src.agent_marketplace.runtime_contract.serialization.load_pem_public_key",
        side_effect=UnsupportedAlgorithm("unsupported public key algorithm"),
    ):
        assert not verify_attestation_signature(signed, test_keys, now=NOW)
        assert not verify_backend_readiness(
            _ready(), _READINESS_KEYS, _ASSESSOR_KEYS, now=NOW)

    class TrustedKeyMap(dict):
        pass

    assert not verify_attestation_signature(
        signed, TrustedKeyMap(test_keys), now=NOW)

    class AttestationSubclass(ArtifactAttestation):
        pass

    class TrustedKeySubclass(TrustedAttestationKey):
        pass

    subclass_attestation = AttestationSubclass.model_validate(
        signed.model_dump())
    subclass_key = TrustedKeySubclass.model_validate(
        test_keys["review-key-1"].model_dump())
    assert not verify_attestation_signature(
        subclass_attestation, test_keys, now=NOW)
    assert not verify_artifact_bytes(subclass_attestation, ARTIFACT_BYTES)
    assert not verify_attestation_signature(
        signed, {"review-key-1": subclass_key}, now=NOW)
    mutated_key = test_keys["review-key-1"].model_copy(
        update={"expires_at": NOW - timedelta(seconds=1)})
    assert not verify_attestation_signature(
        signed, {"review-key-1": mutated_key}, now=NOW)
    assert not verify_attestation_signature(signed, {}, now=NOW)
    oversized_trusted_keys = {
        f"unrelated-{index}": test_keys["review-key-1"]
        for index in range(257)
    }
    assert not verify_attestation_signature(
        signed, oversized_trusted_keys, now=NOW)
    assert not verify_attestation_signature(
        signed, {"x" * 161: test_keys["review-key-1"]}, now=NOW)
    assert not verify_attestation_signature(
        signed.model_copy(update={"sha256": "b" * 64}), test_keys, now=NOW)
    malformed_attestation = signed.model_copy(update={"sha256": "not-a-digest"})
    assert not verify_attestation_signature(
        malformed_attestation, test_keys, now=NOW)
    assert not verify_artifact_bytes(malformed_attestation, ARTIFACT_BYTES)
    assert not verify_attestation_signature(
        signed.model_copy(update={"signature": "not-base64%%%"}),
        test_keys, now=NOW)
    assert not verify_attestation_signature(
        signed, {"review-key-1": _trusted_key(public_pem, revoked_at=NOW)}, now=NOW)
    assert not verify_attestation_signature(
        signed, {"review-key-1": _trusted_key(public_pem, expires_at=NOW)}, now=NOW)
    assert not verify_attestation_signature(
        signed, {"review-key-1": _trusted_key(public_pem, signer_id="other")}, now=NOW)
    assert not verify_attestation_signature(
        signed, {"review-key-1": _trusted_key(
            public_pem, valid_from=NOW + timedelta(minutes=1))}, now=NOW)
    assert not verify_attestation_signature(
        _attestation(created_at=NOW + timedelta(minutes=1)), test_keys, now=NOW)

    old_time = NOW - timedelta(days=91)
    long_lived_key = _trusted_key(
        public_pem, valid_from=NOW - timedelta(days=120),
        expires_at=NOW + timedelta(days=120))
    old_unsigned = _attestation(created_at=old_time, signature="pending")
    old_signature = base64.urlsafe_b64encode(
        private_key.sign(attestation_signing_payload(old_unsigned))
    ).decode().rstrip("=")
    old_signed = old_unsigned.model_copy(update={"signature": old_signature})
    assert not verify_attestation_signature(
        old_signed, {"review-key-1": long_lived_key}, now=NOW)
    assert verify_attestation_signature(
        old_signed, {"review-key-1": long_lived_key}, now=NOW,
        maximum_age_seconds=100 * 24 * 60 * 60)


def test_artifact_bytes_are_bounded_and_match_signed_digest():
    artifact = b"minimal inert wasm artifact fixture"
    attestation = _attestation(sha256=hashlib.sha256(artifact).hexdigest())

    class HostileBytes(bytes):
        def __len__(self):
            raise RuntimeError("hostile length")

    assert verify_artifact_bytes(attestation, artifact)
    assert not verify_artifact_bytes(attestation, artifact + b"tampered")
    assert not verify_artifact_bytes(attestation, artifact, maximum_bytes=4)
    assert not verify_artifact_bytes(attestation, bytearray(artifact))
    assert not verify_artifact_bytes(attestation, HostileBytes(artifact))


def test_policy_limits_reject_boolean_integer_coercion():
    attestation = _attestation()
    readiness = _ready()
    evidence = _evidence_for(readiness.backend)
    source = _source_evidence_for(readiness.backend)

    assert not verify_artifact_bytes(attestation, ARTIFACT_BYTES, maximum_bytes=True)
    assert not verify_attestation_signature(
        attestation, _TRUSTED_KEYS, now=NOW, maximum_age_seconds=True)
    assert not verify_backend_readiness(
        readiness, _READINESS_KEYS, _ASSESSOR_KEYS, now=NOW,
        maximum_validity_seconds=True)
    assert not verify_backend_evidence(
        readiness, evidence, source, now=NOW, maximum_total_bytes=True)
    assert not verify_backend_evidence(
        readiness, evidence, source, now=NOW, maximum_age_seconds=True)
    assert _decide(maximum_input_bytes=True).reason == "resource_limit_exceeded"
    assert _decide(maximum_deadline_seconds=True).reason == "resource_limit_exceeded"


def test_admission_decision_requires_state_and_reason_consistency():
    decision = {
        "admitted": True, "reason": "admitted",
        "backend": RuntimeBackend.WASM_WASI, "artifact_sha256": DIGEST,
        "policy_revision": "policy-v1",
    }
    assert AdmissionDecision(**decision).admitted
    with pytest.raises(ValidationError, match="consistent"):
        AdmissionDecision(**{**decision, "reason": "artifact_revoked"})
    with pytest.raises(ValidationError, match="consistent"):
        AdmissionDecision(**{**decision, "admitted": False})


@pytest.mark.parametrize("field", ["reason", "artifact_sha256", "policy_revision"])
def test_admission_decision_rejects_string_subclasses(field):
    class HostileText(str):
        pass

    decision = {
        "admitted": True, "reason": "admitted",
        "backend": RuntimeBackend.WASM_WASI, "artifact_sha256": DIGEST,
        "policy_revision": "policy-v1",
    }
    decision[field] = HostileText(decision[field])
    with pytest.raises(ValidationError, match="admission decision text fields must be built-in strings"):
        AdmissionDecision(**decision)


def test_admission_decision_rejects_boolean_coercion():
    decision = {
        "admitted": "false", "reason": "artifact_not_approved",
        "backend": RuntimeBackend.WASM_WASI, "artifact_sha256": DIGEST,
        "policy_revision": "policy-v1",
    }
    with pytest.raises(ValidationError):
        AdmissionDecision(**decision)
    decision["admitted"] = 0
    with pytest.raises(ValidationError):
        AdmissionDecision(**decision)


def test_contracts_reject_unknown_fields_and_noncanonical_digest():
    with pytest.raises(ValidationError):
        _request(input_bytes=True)
    with pytest.raises(ValidationError):
        _request(deadline_seconds=False)
    with pytest.raises(ValidationError):
        _ready(generation=True)
    with pytest.raises(ValidationError):
        _ready(enabled=1)
    with pytest.raises(ValidationError):
        _request(unreviewed_payload="not allowed")
    with pytest.raises(ValidationError):
        _request(sha256="A" * 64)
    with pytest.raises(ValidationError):
        _attestation(backend="automatic")


def test_audit_event_contains_bounded_metadata_not_input_or_output_payloads():
    event = RuntimeAuditEvent(
        event_id="evt-1", occurred_at=NOW, event_type="admission_denied",
        run_id="run-1", tenant_id="tenant-1", agent_id="agent-1",
        version="1.2.3", backend=RuntimeBackend.WASM_WASI,
        artifact_sha256=DIGEST, policy_revision="policy-v1",
        reason_code="artifact_not_approved")
    assert "input" not in event.model_dump()
    assert "output" not in event.model_dump()

    class HostileEventText(str):
        def __eq__(self, other):
            raise AssertionError("string subclass equality must not run")

    with pytest.raises(ValidationError, match="built-in strings"):
        RuntimeAuditEvent(**{
            **event.model_dump(), "event_type": HostileEventText("admission_denied"),
        })
    with pytest.raises(ValidationError):
        RuntimeAuditEvent(**{**event.model_dump(), "input": {"secret": "x"}})
    with pytest.raises(ValidationError, match="timezone"):
        RuntimeAuditEvent(**{**event.model_dump(), "occurred_at": NOW.replace(tzinfo=None)})

    class HostileDateTime(datetime):
        def utcoffset(self):
            raise AssertionError("datetime subclass callbacks must not run")

    hostile_datetime = HostileDateTime(
        NOW.year, NOW.month, NOW.day, NOW.hour, NOW.minute, NOW.second,
        NOW.microsecond, tzinfo=UTC)
    with pytest.raises(ValidationError, match="timestamp"):
        RuntimeAuditEvent(**{
            **event.model_dump(), "occurred_at": hostile_datetime,
        })

    class HostileTimestamp(str):
        def replace(self, *args, **kwargs):
            raise AssertionError("string subclass callbacks must not run")

    with pytest.raises(ValidationError, match="timestamp"):
        RuntimeAuditEvent(**{
            **event.model_dump(), "occurred_at": HostileTimestamp(NOW.isoformat()),
        })
