"""Tenant isolation, retention, and integrity tests for runtime audit metadata."""
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from itertools import pairwise

import fakeredis
import pytest
from pydantic import ValidationError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.agent_marketplace.audit_ledger import (
    AuditCheckpoint,
    AuditLedgerError,
    RuntimeAuditLedger,
    _checkpoint_payload,
)
from src.agent_marketplace.runtime_contract import (
    RuntimeAuditEvent,
    RuntimeBackend,
    TrustedAttestationKey,
)


def _event(tenant_id="tenant-a", suffix="1"):
    return RuntimeAuditEvent(
        event_id=f"event-{suffix}", occurred_at=datetime.now(UTC),
        event_type="admission_denied", run_id=f"run-{suffix}",
        tenant_id=tenant_id, agent_id="agent-a", version="1.0.0",
        backend=RuntimeBackend.WASM_WASI, artifact_sha256="a" * 64,
        policy_revision="policy-1", reason_code="artifact_not_approved")


def _ledger(redis_client=None, max_events=100):
    return RuntimeAuditLedger(
        redis_client or fakeredis.FakeStrictRedis(decode_responses=True),
        max_events_per_tenant=max_events)


def test_audit_ledger_limits_require_exact_integer_types():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    with pytest.raises(ValueError, match="positive integer"):
        RuntimeAuditLedger(redis_client, max_events_per_tenant=True)
    with pytest.raises(ValueError, match="nonnegative integer"):
        RuntimeAuditLedger(redis_client, maximum_future_skew_seconds=True)


def test_audit_read_limit_rejects_boolean_coercion():
    ledger = _ledger()
    with pytest.raises(ValueError, match="limit must be an integer"):
        ledger.read("tenant-a", limit=True)


def test_audit_tenant_ids_are_not_coerced_from_non_strings():
    ledger = _ledger()
    with pytest.raises(AuditLedgerError, match="tenant must match"):
        ledger.append(123, _event())
    with pytest.raises(AuditLedgerError, match="nonempty string"):
        ledger.read(123)
    assert not ledger.verify(123)
    assert ledger.verify("123")


def test_append_revalidates_runtime_events_copied_with_invalid_updates():
    ledger = _ledger()
    malformed = _event().model_copy(update={
        "occurred_at": datetime.now(UTC).replace(tzinfo=None),
    })
    with pytest.raises(AuditLedgerError, match="invalid audit event contract"):
        ledger.append("tenant-a", malformed)
    assert ledger.verify("tenant-a")


def test_audit_ledger_rejects_events_with_far_future_timestamps():
    ledger = _ledger()
    future_event = _event().model_copy(update={
        "occurred_at": datetime.now(UTC) + timedelta(minutes=6)})

    with pytest.raises(AuditLedgerError, match="timestamp is too far in the future"):
        ledger.append("tenant-a", future_event)
    assert ledger.verify("tenant-a")


def test_audit_ledger_is_tenant_partitioned_and_rejects_mismatched_tenant():
    ledger = _ledger()
    record = ledger.append("tenant-a", _event())
    ledger.append("tenant-b", _event(tenant_id="tenant-b"))

    assert record.sequence == 1
    assert ledger.verify("tenant-a")
    assert ledger.verify("tenant-b")
    assert [item.event.tenant_id for item in ledger.read("tenant-a")] == ["tenant-a"]
    with pytest.raises(AuditLedgerError, match="tenant must match"):
        ledger.append("tenant-a", _event(tenant_id="tenant-b", suffix="cross"))


def test_duplicate_event_ids_are_idempotent_within_retained_window():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client, max_events=3)
    event = _event()

    first = ledger.append("tenant-a", event)
    retried = ledger.append("tenant-a", event)
    records_key, _ = ledger._keys("tenant-a")
    assert retried == first
    assert redis_client.llen(records_key) == 1
    assert ledger.verify("tenant-a")

    conflicting = event.model_copy(update={"reason_code": "different-denial"})
    with pytest.raises(AuditLedgerError, match="different contents"):
        ledger.append("tenant-a", conflicting)
    assert redis_client.llen(records_key) == 1
    assert ledger.verify("tenant-a")


def test_audit_ledger_keeps_bounded_window_and_verifies_chain_head():
    ledger = _ledger(max_events=2)
    for index in range(4):
        ledger.append("tenant-a", _event(suffix=str(index)))

    retained = ledger.read("tenant-a", limit=2)
    assert [record.sequence for record in retained] == [3, 4]
    assert retained[1].previous_hash == retained[0].event_hash
    assert ledger.verify("tenant-a")
    with pytest.raises(ValueError, match="limit"):
        ledger.read("tenant-a", limit=3)


def test_audit_ledger_detects_record_tampering_and_head_mismatch():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, head_key = ledger._keys("tenant-a")

    original = json.loads(redis_client.lindex(records_key, 0))
    original["event"]["reason_code"] = "changed"
    redis_client.lset(records_key, 0, json.dumps(original))
    assert not ledger.verify("tenant-a")
    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")
    with pytest.raises(AuditLedgerError, match="invalid audit record encoding"):
        ledger.append("tenant-a", _event(suffix="after-tamper"))

    redis_client.lset(records_key, 0, "{}")
    assert not ledger.verify("tenant-a")
    redis_client.hset(head_key, "event_hash", "b" * 64)
    assert not ledger.verify("tenant-a")


def test_append_watches_retained_records_against_concurrent_mutation(monkeypatch):
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, _ = ledger._keys("tenant-a")
    original_record = json.loads(redis_client.lindex(records_key, 0))
    original_record["event"]["reason_code"] = "racing-tamper"
    base_pipeline = redis_client.pipeline
    mutate_once = {"pending": True}

    class MutatingPipeline:
        def __init__(self, pipeline):
            self.pipeline = pipeline

        def __enter__(self):
            self.pipeline.__enter__()
            return self

        def __exit__(self, *args):
            return self.pipeline.__exit__(*args)

        def __getattr__(self, name):
            return getattr(self.pipeline, name)

        def execute(self, *args, **kwargs):
            if mutate_once["pending"]:
                mutate_once["pending"] = False
                redis_client.lset(records_key, 0, json.dumps(original_record))
            return self.pipeline.execute(*args, **kwargs)

    monkeypatch.setattr(
        redis_client, "pipeline",
        lambda *args, **kwargs: MutatingPipeline(base_pipeline(*args, **kwargs)))
    with pytest.raises(AuditLedgerError, match="invalid audit record encoding"):
        ledger.append("tenant-a", _event(suffix="racing-append"))
    assert mutate_once["pending"] is False
    assert redis_client.llen(records_key) == 1


def test_retained_window_anchor_detects_missing_prefix_record():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client, max_events=3)
    for index in range(5):
        ledger.append("tenant-a", _event(suffix=str(index)))
    records_key, _ = ledger._keys("tenant-a")
    assert [item.sequence for item in ledger.read("tenant-a", limit=3)] == [3, 4, 5]
    assert ledger.verify("tenant-a")

    redis_client.lpop(records_key)
    assert not ledger.verify("tenant-a")


def test_audit_record_sequence_rejects_coercible_non_integer_values():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, _ = ledger._keys("tenant-a")
    original = json.loads(redis_client.lindex(records_key, 0))

    for invalid_sequence in (True, 1.0, "1"):
        altered = {**original, "sequence": invalid_sequence}
        redis_client.lset(records_key, 0, json.dumps(altered))
        assert not ledger.verify("tenant-a")
        redis_client.lset(records_key, 0, json.dumps(original))


def test_audit_head_rejects_non_utf8_field_names_fail_closed():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=False)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    _, head_key = ledger._keys("tenant-a")
    redis_client.hset(head_key, b"\xff", b"value")

    assert not ledger.verify("tenant-a")
    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")


def test_audit_head_rejects_noncanonical_sequence_encoding():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    _, head_key = ledger._keys("tenant-a")

    for field in ("sequence", "first_sequence"):
        original = redis_client.hget(head_key, field)
        redis_client.hset(head_key, field, "+1")
        assert not ledger.verify("tenant-a")
        redis_client.hset(head_key, field, "01")
        assert not ledger.verify("tenant-a")
        redis_client.hset(head_key, field, original)
    assert ledger.verify("tenant-a")

    # Extra or partially populated head metadata must not be ignored.
    redis_client.hset(head_key, "unexpected", "value")
    assert not ledger.verify("tenant-a")
    redis_client.hdel(head_key, "unexpected")
    redis_client.hdel(head_key, "first_previous_hash")
    assert not ledger.verify("tenant-a")


def test_audit_record_decoder_rejects_duplicate_json_keys():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, _ = ledger._keys("tenant-a")
    original = redis_client.lindex(records_key, 0)

    # A permissive decoder would use the final sequence key and recover the
    # original record, hiding the duplicate-key mutation from chain checks.
    redis_client.lset(records_key, 0, '{"sequence":false,' + original[1:])
    assert not ledger.verify("tenant-a")
    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")


def test_legacy_unanchored_ledger_can_be_verified_and_upgraded_on_append():

    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client, max_events=3)
    for index in range(3):
        ledger.append("tenant-a", _event(suffix=str(index)))
    _, head_key = ledger._keys("tenant-a")
    redis_client.hdel(head_key, "first_sequence", "first_previous_hash")

    assert ledger.verify("tenant-a")
    ledger.append("tenant-a", _event(suffix="new"))
    assert ledger.verify("tenant-a")


def test_retention_limit_can_be_reduced_without_breaking_chain():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    larger = _ledger(redis_client, max_events=10)
    for index in range(5):
        larger.append("tenant-a", _event(suffix=str(index)))

    smaller = _ledger(redis_client, max_events=2)
    smaller.append("tenant-a", _event(suffix="after-shrink"))
    assert [item.sequence for item in smaller.read("tenant-a", limit=2)] == [5, 6]
    assert smaller.verify("tenant-a")


def test_signed_checkpoint_is_tenant_bound_and_verifiable_outside_redis():
    now = datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    trusted_key = TrustedAttestationKey(
        key_id="audit-key-1", signer_id="audit-operator",
        public_key_pem=public_key_pem,
        valid_from=now - timedelta(days=1), expires_at=now + timedelta(days=1))
    ledger = _ledger(max_events=2)
    for index in range(3):
        ledger.append("tenant-a", _event(suffix=f"checkpoint-{index}"))

    checkpoint = ledger.create_checkpoint(
        "tenant-a", signer_id="audit-operator", key_id="audit-key-1",
        private_key=private_key, created_at=now)
    trusted_keys = {"audit-key-1": trusted_key}
    assert checkpoint.sequence == 3
    checkpoint_data = checkpoint.model_dump()
    for timestamp in (1_800_000_000, "1800000000"):
        with pytest.raises(ValidationError, match="timestamp"):
            AuditCheckpoint(**{**checkpoint_data, "created_at": timestamp})
    with pytest.raises(ValidationError, match="timezone"):
        AuditCheckpoint(**{
            **checkpoint_data, "created_at": now.replace(tzinfo=None),
        })
    with pytest.raises(ValueError, match="retention window is inconsistent"):
        AuditCheckpoint(**{
            **checkpoint.model_dump(),
            "first_sequence": checkpoint.sequence + 1,
        })
    for counter in ("sequence", "first_sequence"):
        with pytest.raises(ValidationError):
            AuditCheckpoint(**{
                **checkpoint.model_dump(),
                counter: True,
            })
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint.model_copy(update={"first_sequence": checkpoint.sequence + 1}),
        tenant_id="tenant-a", trusted_keys={"audit-key-1": trusted_key}, now=now)
    assert RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys=trusted_keys, now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint.model_copy(update={"signature": checkpoint.signature + "="}),
        tenant_id="tenant-a", trusted_keys=trusted_keys, now=now)
    malformed_checkpoint = checkpoint.model_copy(update={
        "sequence": True, "signature": "pending",
    })
    malformed_signature = base64.urlsafe_b64encode(
        private_key.sign(_checkpoint_payload(malformed_checkpoint))
    ).decode("ascii").rstrip("=")
    malformed_checkpoint = malformed_checkpoint.model_copy(update={
        "signature": malformed_signature,
    })
    assert not RuntimeAuditLedger.verify_checkpoint(
        malformed_checkpoint, tenant_id="tenant-a",
        trusted_keys=trusted_keys, now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys=trusted_keys, now=True)
    assert not ledger.matches_checkpoint(
        checkpoint, "tenant-a", trusted_keys=trusted_keys, now=True)
    assert ledger.matches_checkpoint(
        checkpoint, "tenant-a", trusted_keys=trusted_keys, now=now)
    assert not ledger.matches_checkpoint(
        checkpoint.model_copy(update={"signature": "not-a-valid-signature"}),
        "tenant-a", trusted_keys=trusted_keys, now=now)
    assert not ledger.matches_checkpoint(
        checkpoint, "tenant-b", trusted_keys=trusted_keys, now=now)
    assert not ledger.matches_checkpoint(
        checkpoint, "tenant-a", trusted_keys={"audit-key-1": TrustedAttestationKey(
            key_id="audit-key-1", signer_id="audit-operator",
            public_key_pem=public_key_pem, valid_from=now - timedelta(days=1),
            expires_at=now + timedelta(days=1), revoked_at=now)}, now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-b", trusted_keys=trusted_keys, now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint.model_copy(update={"event_hash": "b" * 64}),
        tenant_id="tenant-a", trusted_keys=trusted_keys, now=now)
    ledger.append("tenant-a", _event(suffix="after-checkpoint"))
    assert not ledger.matches_checkpoint(
        checkpoint, "tenant-a", trusted_keys=trusted_keys, now=now)


def test_signed_checkpoint_rejects_revoked_or_expired_signing_keys():
    now = datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    ledger = _ledger()
    ledger.append("tenant-a", _event())
    checkpoint = ledger.create_checkpoint(
        "tenant-a", signer_id="audit-operator", key_id="audit-key-1",
        private_key=private_key, created_at=now)
    base = {
        "key_id": "audit-key-1", "signer_id": "audit-operator",
        "public_key_pem": public_key_pem,
        "valid_from": now - timedelta(days=1),
        "expires_at": now + timedelta(days=1),
    }
    revoked = TrustedAttestationKey(**{**base, "revoked_at": now})
    expired = TrustedAttestationKey(**{**base, "expires_at": now})
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys={"audit-key-1": revoked},
        now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys={"audit-key-1": expired},
        now=now)


def test_concurrent_appends_have_a_single_ordered_chain():
    ledger = _ledger()
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(
            lambda index: ledger.append("tenant-a", _event(suffix=str(index))),
            range(32)))

    assert sorted(record.sequence for record in records) == list(range(1, 33))
    assert ledger.verify("tenant-a")
    stored = ledger.read("tenant-a", limit=32)
    assert all(left.sequence + 1 == right.sequence
               and right.previous_hash == left.event_hash
               for left, right in pairwise(stored))
