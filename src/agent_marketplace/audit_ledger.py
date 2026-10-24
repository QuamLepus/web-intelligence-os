"""Tenant-partitioned, bounded hash-linked storage for runtime audit metadata.

This ledger detects accidental/partial record changes within its retained
window. Redis administrators can rewrite both records and heads; it is not an
immutable or externally anchored audit archive.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, model_validator
from redis.exceptions import WatchError

from src.agent_marketplace.runtime_contract import (
    RuntimeAuditEvent,
    StrictContract,
    TrustedAttestationKey,
)


class AuditLedgerError(ValueError):
    """Rejected audit append or invalid ledger contents."""


@dataclass(frozen=True)
class AuditRecord:
    sequence: int
    previous_hash: str
    event_hash: str
    event: RuntimeAuditEvent

    def to_json(self) -> str:
        return json.dumps({
            "sequence": self.sequence,
            "previous_hash": self.previous_hash,
            "event_hash": self.event_hash,
            "event": self.event.model_dump(mode="json"),
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _canonical_event(event: RuntimeAuditEvent) -> dict[str, Any]:
    return event.model_dump(mode="json")


def _record_hash(sequence: int, previous_hash: str,
                 event_data: dict[str, Any]) -> str:
    payload = json.dumps({
        "sequence": sequence,
        "previous_hash": previous_hash,
        "event": event_data,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
       allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class AuditCheckpoint(StrictContract):
    """Signed checkpoint that can be exported to an independently protected store."""

    tenant_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence: int = Field(ge=0)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    first_sequence: int = Field(ge=1)
    first_previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    signer_id: str = Field(min_length=1, max_length=160)
    key_id: str = Field(min_length=1, max_length=160)
    signature_algorithm: Literal["ed25519"] = "ed25519"
    signature: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def _retained_window_is_consistent(self) -> "AuditCheckpoint":
        zero_hash = "0" * 64
        if self.sequence == 0:
            if (self.first_sequence != 1 or self.event_hash != zero_hash
                    or self.first_previous_hash != zero_hash):
                raise ValueError("empty checkpoint must use the zero-chain anchor")
        elif (self.first_sequence > self.sequence
              or (self.first_sequence == 1
                  and self.first_previous_hash != zero_hash)):
            raise ValueError("checkpoint retention window is inconsistent")
        return self


def _checkpoint_payload(checkpoint: AuditCheckpoint) -> bytes:
    created_at = checkpoint.created_at
    if created_at.tzinfo is None or created_at.utcoffset() is None:
        raise ValueError("checkpoint timestamp must include a timezone")
    value = checkpoint.model_dump(mode="json", exclude={"signature"})
    value["created_at"] = created_at.astimezone(UTC).isoformat()
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


class RuntimeAuditLedger:
    """Append bounded audit metadata per tenant with optimistic concurrency."""

    KEY_PREFIX = "wcp:v1:agent_runtime:audit"
    ZERO_HASH = "0" * 64

    def __init__(
        self,
        redis_client,
        *,
        max_events_per_tenant: int = 5000,
        maximum_future_skew_seconds: int = 300,
    ) -> None:
        if max_events_per_tenant < 1:
            raise ValueError("max_events_per_tenant must be positive")
        if maximum_future_skew_seconds < 0:
            raise ValueError("maximum_future_skew_seconds must not be negative")
        self.r = redis_client
        self.max_events = max_events_per_tenant
        self.maximum_future_skew = timedelta(seconds=maximum_future_skew_seconds)

    @classmethod
    def _keys(cls, tenant_id: str) -> tuple[str, str]:
        # The tenant key is a digest, so raw tenant identifiers never enter Redis keys.
        tenant_hash = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return (f"{cls.KEY_PREFIX}:{tenant_hash}:records",
                f"{cls.KEY_PREFIX}:{tenant_hash}:head")

    @staticmethod
    def _text(value: Any) -> str:
        return value.decode("utf-8") if isinstance(value, bytes) else str(value)

    @classmethod
    def _text_mapping(cls, value: dict[Any, Any]) -> dict[str, str]:
        return {cls._text(key): cls._text(item) for key, item in value.items()}

    def append(self, tenant_id: str, event: RuntimeAuditEvent) -> AuditRecord:
        tenant_id = str(tenant_id)
        if not tenant_id or event.tenant_id != tenant_id:
            raise AuditLedgerError("event tenant must match ledger tenant")
        occurred_at = event.occurred_at.astimezone(UTC)
        if occurred_at > datetime.now(UTC) + self.maximum_future_skew:
            raise AuditLedgerError("event timestamp is too far in the future")
        records_key, head_key = self._keys(tenant_id)
        with self.r.pipeline() as pipe:
            while True:
                try:
                    # Protect both the logical head and retained bytes from
                    # concurrent appends or out-of-band record mutation.
                    pipe.watch(head_key, records_key)
                    head = self._text_mapping(pipe.hgetall(head_key))
                    # Event IDs are idempotency keys within the retained window.
                    # The window is bounded by max_events, so this scan is bounded.
                    existing_records = self._decode_records(
                        pipe.lrange(records_key, 0, -1))
                    if not self._verify_snapshot(tenant_id, existing_records, head):
                        raise AuditLedgerError(
                            "cannot append to an invalid audit ledger")
                    event_data = _canonical_event(event)
                    for existing in existing_records:
                        if existing.event.event_id == event.event_id:
                            if _canonical_event(existing.event) != event_data:
                                raise AuditLedgerError(
                                    "event ID already exists with different contents")
                            return existing
                    sequence = int(head.get("sequence", 0)) + 1
                    previous_hash = head.get("event_hash", self.ZERO_HASH)
                    record = AuditRecord(
                        sequence=sequence,
                        previous_hash=previous_hash,
                        event_hash=_record_hash(sequence, previous_hash, event_data),
                        event=event,
                    )
                    current_length = pipe.llen(records_key)
                    trim_count = max(0, current_length + 1 - self.max_events)
                    raw_evicted = (pipe.lrange(records_key, 0, trim_count - 1)
                                   if trim_count else [])
                    if "first_sequence" in head and "first_previous_hash" in head:
                        first_sequence = int(head["first_sequence"])
                        first_previous_hash = head["first_previous_hash"]
                    elif current_length:
                        raw_first = (raw_evicted[0] if raw_evicted
                                     else pipe.lindex(records_key, 0))
                        if raw_first is None:
                            raise AuditLedgerError("audit retention anchor is missing")
                        oldest = self._decode_records([raw_first])[0]
                        first_sequence = oldest.sequence
                        first_previous_hash = oldest.previous_hash
                    else:
                        first_sequence = 1
                        first_previous_hash = self.ZERO_HASH
                    if raw_evicted:
                        expected_sequence = first_sequence
                        expected_previous_hash = first_previous_hash
                        evicted = self._decode_records(raw_evicted)
                        for old_record in evicted:
                            old_event = _canonical_event(old_record.event)
                            if (old_record.sequence != expected_sequence
                                    or old_record.previous_hash != expected_previous_hash
                                    or old_record.event_hash != _record_hash(
                                        old_record.sequence, old_record.previous_hash,
                                        old_event)):
                                raise AuditLedgerError(
                                    "audit retention anchor is invalid")
                            expected_sequence += 1
                            expected_previous_hash = old_record.event_hash
                        first_sequence = expected_sequence
                        first_previous_hash = expected_previous_hash
                    pipe.multi()
                    pipe.rpush(records_key, record.to_json())
                    pipe.ltrim(records_key, -self.max_events, -1)
                    pipe.hset(head_key, mapping={
                        "sequence": sequence, "event_hash": record.event_hash,
                        "first_sequence": first_sequence,
                        "first_previous_hash": first_previous_hash})
                    pipe.execute()
                    return record
                except WatchError:
                    continue

    def _decode_records(self, raw_records: list[Any]) -> list[AuditRecord]:
        records = []
        for raw in raw_records:
            try:
                value = json.loads(self._text(raw))
                records.append(AuditRecord(
                    sequence=int(value["sequence"]),
                    previous_hash=value["previous_hash"],
                    event_hash=value["event_hash"],
                    event=RuntimeAuditEvent.model_validate(value["event"]),
                ))
            except (KeyError, TypeError, ValueError) as exc:
                raise AuditLedgerError("invalid audit record encoding") from exc
        return records

    def read(self, tenant_id: str, *, limit: int | None = None) -> list[AuditRecord]:
        limit = min(100, self.max_events) if limit is None else limit
        if not 1 <= limit <= self.max_events:
            raise ValueError("limit must be between 1 and max_events_per_tenant")
        records_key, _ = self._keys(str(tenant_id))
        return self._decode_records(self.r.lrange(records_key, -limit, -1))

    def _snapshot(self, tenant_id: str) -> tuple[list[AuditRecord], dict[str, str]]:
        records_key, head_key = self._keys(str(tenant_id))
        with self.r.pipeline(transaction=True) as pipe:
            pipe.lrange(records_key, -self.max_events, -1)
            pipe.hgetall(head_key)
            raw_records, raw_head = pipe.execute()
        return self._decode_records(raw_records), self._text_mapping(raw_head)

    @staticmethod
    def _verify_snapshot(tenant_id: str, records: list[AuditRecord],
                         head: dict[str, str]) -> bool:
        if not records:
            return not head
        try:
            first_sequence = int(head.get("first_sequence", records[0].sequence))
            first_previous_hash = head.get(
                "first_previous_hash", records[0].previous_hash)
        except (TypeError, ValueError):
            return False
        if (records[0].sequence != first_sequence
                or records[0].previous_hash != first_previous_hash):
            return False
        previous = first_previous_hash
        prior_sequence = first_sequence - 1
        for record in records:
            event_data = _canonical_event(record.event)
            if (record.sequence != prior_sequence + 1
                    or record.event.tenant_id != str(tenant_id)
                    or record.previous_hash != previous
                    or record.event_hash != _record_hash(
                        record.sequence, record.previous_hash, event_data)):
                return False
            previous = record.event_hash
            prior_sequence = record.sequence
        try:
            return (int(head.get("sequence", -1)) == records[-1].sequence
                    and head.get("event_hash", "") == records[-1].event_hash)
        except (TypeError, ValueError):
            return False

    def verify(self, tenant_id: str) -> bool:
        """Verify the retained chain and its head; an empty ledger is valid."""
        try:
            records, head = self._snapshot(str(tenant_id))
        except AuditLedgerError:
            return False
        return self._verify_snapshot(str(tenant_id), records, head)

    def create_checkpoint(
        self,
        tenant_id: str,
        *,
        signer_id: str,
        key_id: str,
        private_key: Ed25519PrivateKey,
        created_at: datetime | None = None,
    ) -> AuditCheckpoint:
        """Sign the current verified head for caller-managed external storage.

        The signing key is only used in memory here and is never persisted by
        this class. The returned checkpoint must be exported independently to
        protect it from administrators who can rewrite this Redis database.
        """
        if not isinstance(private_key, Ed25519PrivateKey):
            raise AuditLedgerError("checkpoint signing requires an Ed25519 private key")
        tenant_id = str(tenant_id)
        if not tenant_id:
            raise AuditLedgerError("tenant ID is required for a checkpoint")
        try:
            records, head = self._snapshot(tenant_id)
        except AuditLedgerError as exc:
            raise AuditLedgerError("cannot checkpoint an invalid audit ledger") from exc
        if not self._verify_snapshot(tenant_id, records, head):
            raise AuditLedgerError("cannot checkpoint an invalid audit ledger")
        timestamp = created_at or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise AuditLedgerError("checkpoint timestamp must include a timezone")
        checkpoint = AuditCheckpoint(
            tenant_sha256=hashlib.sha256(tenant_id.encode("utf-8")).hexdigest(),
            sequence=int(head.get("sequence", 0)),
            event_hash=head.get("event_hash", self.ZERO_HASH),
            first_sequence=int(head.get("first_sequence", 1)),
            first_previous_hash=head.get("first_previous_hash", self.ZERO_HASH),
            created_at=timestamp,
            signer_id=signer_id,
            key_id=key_id,
            signature="pending",
        )
        signature = base64.urlsafe_b64encode(
            private_key.sign(_checkpoint_payload(checkpoint))).decode("ascii").rstrip("=")
        return checkpoint.model_copy(update={"signature": signature})

    def matches_checkpoint(
        self,
        checkpoint: AuditCheckpoint,
        tenant_id: str,
        *,
        trusted_keys: dict[str, TrustedAttestationKey],
        now: datetime | None = None,
    ) -> bool:
        """Verify a checkpoint signature and compare it to the current ledger.

        Requiring trusted keys here prevents callers from accidentally treating
        a merely well-shaped, unsigned checkpoint as an external trust anchor.
        """
        tenant_id = str(tenant_id)
        tenant_hash = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        if (checkpoint.tenant_sha256 != tenant_hash
                or not self.verify_checkpoint(
                    checkpoint, tenant_id=tenant_id,
                    trusted_keys=trusted_keys, now=now)):
            return False
        try:
            records, head = self._snapshot(tenant_id)
        except AuditLedgerError:
            return False
        if not self._verify_snapshot(tenant_id, records, head):
            return False
        try:
            return (
                int(head.get("sequence", 0)) == checkpoint.sequence
                and head.get("event_hash", self.ZERO_HASH) == checkpoint.event_hash
                and int(head.get("first_sequence", 1)) == checkpoint.first_sequence
                and head.get("first_previous_hash", self.ZERO_HASH)
                == checkpoint.first_previous_hash
            )
        except (TypeError, ValueError):
            return False

    @staticmethod
    def verify_checkpoint(
        checkpoint: AuditCheckpoint,
        *,
        tenant_id: str,
        trusted_keys: dict[str, TrustedAttestationKey],
        now: datetime | None = None,
    ) -> bool:
        """Verify checkpoint structure, signature, tenant, signer, and key status."""
        zero_hash = RuntimeAuditLedger.ZERO_HASH
        if (checkpoint.sequence == 0
                and (checkpoint.first_sequence != 1
                     or checkpoint.event_hash != zero_hash
                     or checkpoint.first_previous_hash != zero_hash)):
            return False
        if (checkpoint.sequence > 0
                and (checkpoint.first_sequence > checkpoint.sequence
                     or (checkpoint.first_sequence == 1
                         and checkpoint.first_previous_hash != zero_hash))):
            return False
        expected_tenant = hashlib.sha256(str(tenant_id).encode("utf-8")).hexdigest()
        if (checkpoint.signature_algorithm != "ed25519"
                or checkpoint.tenant_sha256 != expected_tenant):
            return False
        key = trusted_keys.get(checkpoint.key_id)
        if (key is None or key.key_id != checkpoint.key_id
                or key.signer_id != checkpoint.signer_id):
            return False
        current_time = now or datetime.now(UTC)
        signed_at = checkpoint.created_at
        if (current_time.tzinfo is None or current_time.utcoffset() is None
                or signed_at.tzinfo is None or signed_at.utcoffset() is None):
            return False
        current_time = current_time.astimezone(UTC)
        signed_at = signed_at.astimezone(UTC)
        if (signed_at > current_time
                or signed_at < key.valid_from.astimezone(UTC)
                or signed_at >= key.expires_at.astimezone(UTC)
                or (key.revoked_at is not None
                    and current_time >= key.revoked_at.astimezone(UTC))):
            return False
        try:
            public_key = serialization.load_pem_public_key(
                key.public_key_pem.encode("ascii"))
            if not isinstance(public_key, Ed25519PublicKey):
                return False
            encoded = checkpoint.signature.encode("ascii")
            signature = base64.b64decode(
                encoded + b"=" * (-len(encoded) % 4),
                altchars=b"-_", validate=True)
            public_key.verify(signature, _checkpoint_payload(checkpoint))
        except (ValueError, TypeError, UnicodeEncodeError, InvalidSignature):
            return False
        return True
