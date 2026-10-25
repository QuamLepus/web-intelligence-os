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

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, ValidationError, field_validator, model_validator
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


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Parse a JSON object while rejecting ambiguous duplicate keys."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _parse_canonical_sequence(value: object, *, minimum: int = 0) -> int:
    """Parse a Redis sequence only in its canonical unsigned-decimal form."""
    if (not isinstance(value, str) or not value.isascii() or not value.isdecimal()
            or (len(value) > 1 and value.startswith("0"))):
        raise ValueError("audit head sequence is not canonical")
    sequence = int(value)
    if sequence < minimum:
        raise ValueError("audit head sequence is out of range")
    return sequence


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
    sequence: int = Field(ge=0, strict=True)
    event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    first_sequence: int = Field(ge=1, strict=True)
    first_previous_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    signer_id: str = Field(min_length=1, max_length=160)
    key_id: str = Field(min_length=1, max_length=160)
    signature_algorithm: Literal["ed25519"] = "ed25519"
    signature: str = Field(min_length=1, max_length=256)

    @field_validator("created_at", mode="before")
    @classmethod
    def _timestamp_input_explicit(cls, value: object) -> object:
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(
                    "checkpoint timestamp must be an ISO-8601 datetime with a timezone"
                ) from exc
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("checkpoint timestamp must include a timezone")
            return value
        raise ValueError(
            "checkpoint timestamp must be a datetime or ISO-8601 string with a timezone"
        )

    @field_validator("created_at")
    @classmethod
    def _timestamp_timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("checkpoint timestamp must include a timezone")
        return value

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


def _validated_checkpoint(checkpoint: object) -> AuditCheckpoint | None:
    """Revalidate values because Pydantic model_copy(update=...) skips checks."""
    if type(checkpoint) is not AuditCheckpoint:
        return None
    try:
        data = checkpoint.model_dump(mode="python")
        return AuditCheckpoint.model_validate(data)
    except (AttributeError, TypeError, ValueError, ValidationError):
        return None


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
        if type(max_events_per_tenant) is not int or max_events_per_tenant < 1:
            raise ValueError("max_events_per_tenant must be a positive integer")
        if (type(maximum_future_skew_seconds) is not int
                or maximum_future_skew_seconds < 0):
            raise ValueError("maximum_future_skew_seconds must be a nonnegative integer")
        self.r = redis_client
        self.max_events = max_events_per_tenant
        self.maximum_future_skew = timedelta(seconds=maximum_future_skew_seconds)

    @classmethod
    def _keys(cls, tenant_id: str) -> tuple[str, str]:
        # The tenant key is a digest, so raw tenant identifiers never enter Redis keys.
        if type(tenant_id) is not str or not tenant_id:
            raise AuditLedgerError("tenant ID must be a nonempty built-in string")
        tenant_hash = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        return (f"{cls.KEY_PREFIX}:{tenant_hash}:records",
                f"{cls.KEY_PREFIX}:{tenant_hash}:head")

    @staticmethod
    def _validated_tenant_id(tenant_id: object) -> str:
        if type(tenant_id) is not str or not tenant_id:
            raise AuditLedgerError("tenant ID must be a nonempty string")
        return tenant_id

    @staticmethod
    def _text(value: Any) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8")
        if isinstance(value, str):
            return value
        raise TypeError("Redis audit values must be bytes or strings")

    @classmethod
    def _text_mapping(cls, value: dict[Any, Any]) -> dict[str, str]:
        try:
            result: dict[str, str] = {}
            for key, item in value.items():
                text_key = cls._text(key)
                if text_key in result:
                    raise ValueError("duplicate decoded audit head field")
                result[text_key] = cls._text(item)
            return result
        except (AttributeError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise AuditLedgerError("invalid audit head encoding") from exc

    def append(self, tenant_id: str, event: RuntimeAuditEvent) -> AuditRecord:
        if type(event) is not RuntimeAuditEvent:
            raise AuditLedgerError("invalid audit event contract")
        try:
            event = RuntimeAuditEvent.model_validate(
                event.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError, ValidationError) as exc:
            raise AuditLedgerError("invalid audit event contract") from exc
        try:
            tenant_id = self._validated_tenant_id(tenant_id)
        except AuditLedgerError as exc:
            raise AuditLedgerError("event tenant must match ledger tenant") from exc
        if event.tenant_id != tenant_id:
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
                        # The two watched reads can straddle a concurrent commit.
                        # Commit a harmless command to force WATCH validation; if
                        # the snapshot changed, retry instead of mistaking a
                        # transient mixed view for persistent ledger corruption.
                        pipe.multi()
                        pipe.ping()
                        pipe.execute()
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
                raw_text = self._text(raw)
                value = json.loads(raw_text, object_pairs_hook=_unique_json_object)
                sequence = value["sequence"]
                if type(sequence) is not int or sequence < 0:
                    raise ValueError("audit record sequence must be a nonnegative integer")
                record = AuditRecord(
                    sequence=sequence,
                    previous_hash=value["previous_hash"],
                    event_hash=value["event_hash"],
                    event=RuntimeAuditEvent.model_validate(value["event"]),
                )
                if record.to_json() != raw_text:
                    raise ValueError("audit record encoding is not canonical")
                records.append(record)
            except (KeyError, TypeError, ValueError, RecursionError) as exc:
                raise AuditLedgerError("invalid audit record encoding") from exc
        return records

    def read(self, tenant_id: str, *, limit: int | None = None) -> list[AuditRecord]:
        limit = min(100, self.max_events) if limit is None else limit
        if type(limit) is not int or not 1 <= limit <= self.max_events:
            raise ValueError("limit must be an integer between 1 and max_events_per_tenant")
        tenant_id = self._validated_tenant_id(tenant_id)
        try:
            records, head = self._snapshot(tenant_id)
        except AuditLedgerError as exc:
            raise AuditLedgerError("cannot read an invalid audit ledger") from exc
        if not self._verify_snapshot(tenant_id, records, head):
            raise AuditLedgerError("cannot read an invalid audit ledger")
        return records[-limit:]

    def _snapshot(self, tenant_id: str) -> tuple[list[AuditRecord], dict[str, str]]:
        records_key, head_key = self._keys(tenant_id)
        with self.r.pipeline(transaction=True) as pipe:
            pipe.lrange(records_key, -self.max_events, -1)
            pipe.hgetall(head_key)
            raw_records, raw_head = pipe.execute()
        return self._decode_records(raw_records), self._text_mapping(raw_head)

    @staticmethod
    def _verify_snapshot(tenant_id: str, records: list[AuditRecord],
                         head: dict[str, str]) -> bool:
        if type(tenant_id) is not str or not tenant_id:
            return False
        if not records:
            return not head
        # Accept legacy heads only when both retention-anchor fields are absent;
        # unknown or partially populated fields must not be silently ignored.
        if (set(head) - {"sequence", "event_hash", "first_sequence",
                         "first_previous_hash"}
                or ("first_sequence" in head)
                != ("first_previous_hash" in head)):
            return False
        try:
            first_sequence = (
                _parse_canonical_sequence(head["first_sequence"], minimum=1)
                if "first_sequence" in head else records[0].sequence)
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
                    or record.event.tenant_id != tenant_id
                    or record.previous_hash != previous
                    or record.event_hash != _record_hash(
                        record.sequence, record.previous_hash, event_data)):
                return False
            previous = record.event_hash
            prior_sequence = record.sequence
        try:
            return (_parse_canonical_sequence(head.get("sequence", "-1"))
                    == records[-1].sequence
                    and head.get("event_hash", "") == records[-1].event_hash)
        except (TypeError, ValueError):
            return False

    def verify(self, tenant_id: str) -> bool:
        """Verify the retained chain and its head; an empty ledger is valid."""
        try:
            tenant_id = self._validated_tenant_id(tenant_id)
            records, head = self._snapshot(tenant_id)
        except (AuditLedgerError, TypeError):
            return False
        return self._verify_snapshot(tenant_id, records, head)

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
        tenant_id = self._validated_tenant_id(tenant_id)
        try:
            records, head = self._snapshot(tenant_id)
        except AuditLedgerError as exc:
            raise AuditLedgerError("cannot checkpoint an invalid audit ledger") from exc
        if not self._verify_snapshot(tenant_id, records, head):
            raise AuditLedgerError("cannot checkpoint an invalid audit ledger")
        timestamp = datetime.now(UTC) if created_at is None else created_at
        if (not isinstance(timestamp, datetime)
                or timestamp.tzinfo is None or timestamp.utcoffset() is None):
            raise AuditLedgerError("checkpoint timestamp must be a timezone-aware datetime")
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
        checkpoint = _validated_checkpoint(checkpoint)
        if checkpoint is None:
            return False
        try:
            tenant_id = self._validated_tenant_id(tenant_id)
        except AuditLedgerError:
            return False
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
        checkpoint = _validated_checkpoint(checkpoint)
        if checkpoint is None:
            return False
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
        if type(tenant_id) is not str or not tenant_id:
            return False
        expected_tenant = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        if (checkpoint.signature_algorithm != "ed25519"
                or checkpoint.tenant_sha256 != expected_tenant):
            return False
        if type(trusted_keys) is not dict:
            return False
        try:
            key = trusted_keys.get(checkpoint.key_id)
            if type(key) is not TrustedAttestationKey:
                return False
            key = TrustedAttestationKey.model_validate(
                key.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError, ValidationError):
            return False
        if (key.key_id != checkpoint.key_id
                or key.signer_id != checkpoint.signer_id):
            return False
        if now is None:
            current_time = datetime.now(UTC)
        elif (isinstance(now, datetime)
              and now.tzinfo is not None and now.utcoffset() is not None):
            current_time = now.astimezone(UTC)
        else:
            return False
        signed_at = checkpoint.created_at
        if signed_at.tzinfo is None or signed_at.utcoffset() is None:
            return False
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
            canonical_signature = base64.urlsafe_b64encode(
                signature).decode("ascii").rstrip("=")
            if canonical_signature != checkpoint.signature:
                return False
            public_key.verify(signature, _checkpoint_payload(checkpoint))
        except (ValueError, TypeError, UnicodeEncodeError, InvalidSignature,
                UnsupportedAlgorithm):
            return False
        return True
