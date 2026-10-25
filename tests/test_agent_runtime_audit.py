"""Tenant isolation, retention, and integrity tests for runtime audit metadata."""
import base64
import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, tzinfo
from itertools import pairwise
from unittest.mock import patch

import fakeredis
import pytest
from pydantic import ValidationError
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.agent_marketplace.audit_ledger import (
    AuditCheckpoint,
    AuditRecord,
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


def test_audit_redis_values_reject_string_subclasses():
    class UnsafeRedisText(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("string subclass override must not run")

    with pytest.raises(TypeError, match="built-in bytes or strings"):
        RuntimeAuditLedger._text(UnsafeRedisText("{}"))


def test_audit_decoder_rejects_record_collection_subclasses():
    class UnsafeRecords(list):
        def __iter__(self):
            raise AssertionError("list subclass override must not run")

    with pytest.raises(AuditLedgerError, match="invalid audit record collection"):
        _ledger()._decode_records(UnsafeRecords())


def test_audit_head_decoder_rejects_mapping_subclasses():
    class UnsafeHead(dict):
        def items(self):
            raise AssertionError("mapping subclass override must not run")

    with pytest.raises(AuditLedgerError, match="invalid audit head encoding"):
        RuntimeAuditLedger._text_mapping(UnsafeHead())


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

    class TenantId(str):
        def encode(self, *args, **kwargs):
            raise AssertionError("string subclasses must not be treated as tenant IDs")

    with pytest.raises(AuditLedgerError, match="tenant must match"):
        ledger.append(TenantId("tenant-a"), _event())
    with pytest.raises(AuditLedgerError, match="nonempty string"):
        ledger.read(TenantId("tenant-a"))
    assert not ledger.verify(TenantId("tenant-a"))
    with pytest.raises(AuditLedgerError, match="built-in string"):
        RuntimeAuditLedger._keys(TenantId("tenant-a"))
    assert not RuntimeAuditLedger._verify_snapshot(
        TenantId("tenant-a"), [], {})


def test_snapshot_verifier_rejects_container_subclasses():
    class UnsafeRecords(list):
        def __iter__(self):
            raise AssertionError("record list subclass override must not run")

    class UnsafeHead(dict):
        def __iter__(self):
            raise AssertionError("head mapping subclass override must not run")

    assert not RuntimeAuditLedger._verify_snapshot(
        "tenant-a", UnsafeRecords(), {})
    assert not RuntimeAuditLedger._verify_snapshot(
        "tenant-a", [], UnsafeHead())


def test_snapshot_verifier_rejects_non_builtin_head_fields():
    class UnsafeText(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            raise AssertionError("string subclass equality must not run")

    head_with_subclass_key = {UnsafeText("sequence"): "1"}
    head_with_subclass_value = {"sequence": UnsafeText("1")}

    assert not RuntimeAuditLedger._verify_snapshot(
        "tenant-a", [], head_with_subclass_key)
    assert not RuntimeAuditLedger._verify_snapshot(
        "tenant-a", [], head_with_subclass_value)


def test_snapshot_verifier_rejects_non_audit_record_values():
    assert not RuntimeAuditLedger._verify_snapshot(
        "tenant-a", [object()], {})


@pytest.mark.parametrize(("sequence", "previous_hash"), [
    (True, "0" * 64),
    (1, 7),
    (1, "A" * 64),
])
def test_snapshot_verifier_rejects_malformed_record_fields(sequence, previous_hash):
    record = AuditRecord(
        sequence=sequence, previous_hash=previous_hash, event_hash="0" * 64,
        event=_event())

    assert not RuntimeAuditLedger._verify_snapshot("tenant-a", [record], {})


def test_snapshot_verifier_revalidates_copied_audit_events():
    malformed_event = _event().model_copy(update={"tenant_id": 44})
    zero_hash = "0" * 64
    record = AuditRecord(
        sequence=1, previous_hash=zero_hash, event_hash=zero_hash,
        event=malformed_event)
    head = {
        "sequence": "1", "event_hash": zero_hash,
    }

    assert not RuntimeAuditLedger._verify_snapshot("tenant-a", [record], head)


def test_append_rejects_non_contract_objects_without_coercion():
    ledger = _ledger()
    with pytest.raises(AuditLedgerError, match="invalid audit event contract"):
        ledger.append("tenant-a", object())
    assert ledger.verify("tenant-a")


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


@pytest.mark.parametrize("field,value", [
    ("previous_hash", 7),
    ("event_hash", "A" * 64),
])
def test_audit_decoder_rejects_noncanonical_hash_fields(field, value):
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, _ = ledger._keys("tenant-a")
    stored = json.loads(redis_client.lindex(records_key, 0))
    stored[field] = value
    redis_client.lset(records_key, 0, json.dumps(stored, sort_keys=True,
                                                  separators=(",", ":")))

    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")
    assert not ledger.verify("tenant-a")


def test_create_checkpoint_fails_closed_when_redis_is_unavailable(monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    ledger = _ledger()
    private_key = Ed25519PrivateKey.generate()

    def unavailable(_tenant_id):
        raise RedisConnectionError("redis unavailable")

    monkeypatch.setattr(ledger, "_snapshot", unavailable)
    with pytest.raises(
        AuditLedgerError, match="cannot checkpoint an invalid audit ledger"
    ):
        ledger.create_checkpoint(
            "tenant-a", signer_id="audit-operator", key_id="audit-key",
            private_key=private_key)


def test_read_fails_closed_when_redis_is_unavailable(monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    ledger = _ledger()

    def unavailable(_tenant_id):
        raise RedisConnectionError("redis unavailable")

    monkeypatch.setattr(ledger, "_snapshot", unavailable)
    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")


def test_verify_fails_closed_when_redis_is_unavailable(monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    ledger = _ledger()

    def unavailable(_tenant_id):
        raise RedisConnectionError("redis unavailable")

    monkeypatch.setattr(ledger, "_snapshot", unavailable)
    assert not ledger.verify("tenant-a")


def test_matches_checkpoint_fails_closed_when_redis_is_unavailable(monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    ledger = _ledger()
    now = datetime.now(UTC)
    zero_hash = "0" * 64
    checkpoint = AuditCheckpoint(
        tenant_sha256=hashlib.sha256(b"tenant-a").hexdigest(),
        sequence=0, event_hash=zero_hash, first_sequence=1,
        first_previous_hash=zero_hash, created_at=now,
        signer_id="audit-operator", key_id="audit-key", signature="dummy")
    monkeypatch.setattr(
        ledger, "verify_checkpoint", lambda *args, **kwargs: True)

    def unavailable(_tenant_id):
        raise RedisConnectionError("redis unavailable")

    monkeypatch.setattr(ledger, "_snapshot", unavailable)
    assert not ledger.matches_checkpoint(
        checkpoint, "tenant-a", trusted_keys={}, now=now)


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


def test_audit_record_decoder_rejects_excessive_json_nesting():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, _ = ledger._keys("tenant-a")
    redis_client.lset(records_key, 0, "[" * 2000 + "0" + "]" * 2000)

    assert not ledger.verify("tenant-a")
    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")


def test_audit_record_decoder_rejects_oversized_records():
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    ledger.append("tenant-a", _event())
    records_key, _ = ledger._keys("tenant-a")
    redis_client.lset(records_key, 0, " " * (ledger.MAX_RECORD_BYTES + 1))

    assert not ledger.verify("tenant-a")
    with pytest.raises(AuditLedgerError, match="cannot read an invalid audit ledger"):
        ledger.read("tenant-a")


def test_audit_append_rejects_serialized_records_over_size_limit(monkeypatch):
    redis_client = fakeredis.FakeStrictRedis(decode_responses=True)
    ledger = _ledger(redis_client)
    monkeypatch.setattr(RuntimeAuditLedger, "MAX_RECORD_BYTES", 1)

    with pytest.raises(AuditLedgerError, match="exceeds the byte limit"):
        ledger.append("tenant-a", _event())
    assert ledger.verify("tenant-a")


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
    for invalid_created_at in (0, False, "now", now.replace(tzinfo=None)):
        with pytest.raises(AuditLedgerError, match="timezone-aware datetime"):
            ledger.create_checkpoint(
                "tenant-a", signer_id="audit-operator", key_id="audit-key-1",
                private_key=private_key, created_at=invalid_created_at)

    class HostileDateTime(datetime):
        def utcoffset(self):
            raise AssertionError("datetime subclass callbacks must not run")

    hostile_created_at = HostileDateTime(
        now.year, now.month, now.day, now.hour, now.minute, now.second,
        now.microsecond, tzinfo=UTC)
    with pytest.raises(AuditLedgerError, match="timezone-aware datetime"):
        ledger.create_checkpoint(
            "tenant-a", signer_id="audit-operator", key_id="audit-key-1",
            private_key=private_key, created_at=hostile_created_at)
    trusted_keys = {"audit-key-1": trusted_key}
    assert checkpoint.sequence == 3
    checkpoint_data = checkpoint.model_dump()
    with pytest.raises(ValidationError, match="built-in datetime"):
        AuditCheckpoint(**{**checkpoint_data, "created_at": hostile_created_at})
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
        object(), tenant_id="tenant-a", trusted_keys=trusted_keys, now=now)
    for invalid_key in (
        trusted_key.model_copy(update={"valid_from": now.replace(tzinfo=None)}),
        trusted_key.model_copy(update={"expires_at": now - timedelta(days=2)}),
    ):
        assert not RuntimeAuditLedger.verify_checkpoint(
            checkpoint, tenant_id="tenant-a",
            trusted_keys={"audit-key-1": invalid_key}, now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys={"audit-key-1": object()}, now=now)

    class HostileTrustedKeyMap(dict):
        def get(self, key, default=None):
            raise AssertionError("custom trusted-key map must not be queried")

    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a",
        trusted_keys=HostileTrustedKeyMap(trusted_keys), now=now)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint.model_copy(update={"signature": checkpoint.signature + "="}),
        tenant_id="tenant-a", trusted_keys=trusted_keys, now=now)
    with patch(
        "src.agent_marketplace.audit_ledger.serialization.load_pem_public_key",
        side_effect=UnsupportedAlgorithm("unsupported public key"),
    ):
        assert not RuntimeAuditLedger.verify_checkpoint(
            checkpoint, tenant_id="tenant-a", trusted_keys=trusted_keys, now=now)
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

    class HostileDateTime(datetime):
        def utcoffset(self):
            raise AssertionError("datetime subclass callbacks must not run")

    hostile_now = HostileDateTime(
        now.year, now.month, now.day, now.hour, now.minute, now.second,
        now.microsecond, tzinfo=UTC)
    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys=trusted_keys,
        now=hostile_now)
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


def test_checkpoint_verification_fails_closed_on_recursive_timestamp_validation():
    class RecursiveTimezone(tzinfo):
        def utcoffset(self, dt):
            return dt.utcoffset()

        def dst(self, dt):
            return timedelta(0)

    zero_hash = "0" * 64
    checkpoint = AuditCheckpoint(
        tenant_sha256=hashlib.sha256(b"tenant-a").hexdigest(),
        sequence=0, event_hash=zero_hash, first_sequence=1,
        first_previous_hash=zero_hash, created_at=datetime.now(UTC),
        signer_id="audit-operator", key_id="audit-key", signature="dummy")
    malformed = checkpoint.model_copy(update={
        "created_at": datetime.now().replace(tzinfo=RecursiveTimezone())})

    assert not RuntimeAuditLedger.verify_checkpoint(
        malformed, tenant_id="tenant-a", trusted_keys={})


def test_checkpoint_verification_fails_closed_on_recursive_key_validation():
    class RecursiveTimezone(tzinfo):
        def utcoffset(self, dt):
            return dt.utcoffset()

        def dst(self, dt):
            return timedelta(0)

    now = datetime.now(UTC)
    private_key = Ed25519PrivateKey.generate()
    public_key_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    trusted_key = TrustedAttestationKey(
        key_id="audit-key", signer_id="audit-operator",
        public_key_pem=public_key_pem,
        valid_from=now - timedelta(days=1), expires_at=now + timedelta(days=1))
    malformed_key = trusted_key.model_copy(update={
        "valid_from": datetime.now().replace(tzinfo=RecursiveTimezone())})
    zero_hash = "0" * 64
    checkpoint = AuditCheckpoint(
        tenant_sha256=hashlib.sha256(b"tenant-a").hexdigest(),
        sequence=0, event_hash=zero_hash, first_sequence=1,
        first_previous_hash=zero_hash, created_at=now,
        signer_id="audit-operator", key_id="audit-key", signature="dummy")

    assert not RuntimeAuditLedger.verify_checkpoint(
        checkpoint, tenant_id="tenant-a", trusted_keys={"audit-key": malformed_key},
        now=now)


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
