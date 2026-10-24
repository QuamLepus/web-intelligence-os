# Publisher-supplied agent runtime: security design and launch gates

**Status: design only.** No publisher code is accepted, built, uploaded, or run by
the current agent marketplace. The catalog and the allow-listed managed
`data-curator` remain separate paths. This document is a precondition for any
publisher-supplied executable-agent feature, not evidence that a sandbox exists.

## Security objectives

1. Treat every publisher artifact and every run input as hostile, including
   artifacts from previously approved publishers.
2. Prevent a run from reading host files, credentials, another run's state, or
   another tenant's data.
3. Make outbound network access unavailable unless an operator has explicitly
   enabled a narrow, policy-enforced destination set for that agent/version.
4. Bound CPU, memory, process count, wall time, disk, input, output, and logs;
   terminate runs that exceed the contract.
5. Preserve an auditable chain from a published version to an immutable artifact
   digest, review decision, policy, run, and revocation event.
6. Keep the control plane and the existing API/worker services outside the
   execution boundary.

## Threat model

| Threat | Required control |
|---|---|
| Container or runtime escape | A dedicated, hardened execution plane with a stronger isolation boundary than a normal application container; no privileged mode, host mounts, host PID/network namespaces, or container-runtime socket. |
| Secret theft or cross-tenant reads | No ambient credentials in the runner; no shared application Redis/DB mounts; short-lived, run-scoped capabilities only when required; isolated ephemeral storage wiped after each run. |
| SSRF, scanning, or exfiltration | Network disabled by default; enforce egress outside the guest with default-deny policy and destination/IP validation; block metadata, private, loopback, link-local, and control-plane ranges, including after DNS resolution and redirects. |
| Resource exhaustion or fork bombs | Hard CPU, memory, PID, disk, wall-clock, input/output, and log quotas enforced by the host/runtime, not just by the agent process. Kill the entire run cgroup/VM on timeout. |
| Malicious or compromised artifact | Immutable digest, signed build provenance, malware/dependency review, human approval before initial publication, version revocation, and a kill switch that prevents new runs. |
| Data poisoning or misleading output | Validate outputs against the published schema and size limits; label outputs as untrusted; do not automatically feed them into crawls, indexes, billing, or other agents. |
| Cross-run or cross-tenant side channels | One isolated execution unit per run, no shared writable caches, tenant-scoped authorization at the control plane, and cleanup verified between runs. |
| Abuse, illegal content, or policy evasion | Publisher identity and reporting process, rate and spend limits, audit trail, suspension and revocation controls, retention limits, and an incident response owner before launch. |

## Runtime portfolio (all three boundaries are targets)

The product architecture should support three explicitly selected isolation
classes rather than pretending one runtime fits every artifact:

| Runtime class | Intended artifact | Isolation profile and tradeoff |
|---|---|---|
| WASM/WASI | A constrained WebAssembly component | Narrow, explicit host capabilities and a smaller interface; limits language/runtime compatibility and must still enforce memory, fuel/time, and I/O caps. |
| Sandboxed Kubernetes pool | OCI image on a separate pool configured with a sandbox runtime such as gVisor or Kata | Broader compatibility with containerized agents, but requires its own cluster/pool, admission policy, node hardening, network controls, and runtime-specific escape testing. |
| Dedicated microVM pool | OCI image inside one VM per run | Strong per-run isolation boundary and broad compatibility, at higher startup, capacity, and operational cost. |

These are **all desired backend classes over time**, not permission to run an
artifact in whichever environment happens to be available. Every agent version
must pin exactly one declared runtime class and immutable artifact digest.
Admission rejects unsupported or disabled runtime classes; the scheduler must
never silently fall back to a weaker backend. Each backend implements the same
control-plane contract for identity, input/output limits, deadlines, resource
accounting, cancellation, audit events, and cleanup, while adding its own
runtime-specific policy. A run's security level is the selected backend's
verified profile, not a publisher's self-declared label.

Supporting all three requires separately provisioned and validated execution
pools. A single Docker worker or an abstract interface without enforced backend
policies does not satisfy this design.

### Infrastructure readiness matrix

| Backend | Deployment prerequisites | Required deny-by-default settings |
|---|---|---|
| WASM/WASI | Pinned runtime/version and component ABI; host-side runner with a fuel/instruction budget and memory limiter | No ambient filesystem, environment, clock, randomness, process, or network imports; expose only reviewed host functions; bound stdin/stdout and terminate on fuel/time exhaustion. |
| Sandboxed Kubernetes | Dedicated cluster or node pool with a tested `RuntimeClass` (for example, gVisor), admission policy, and an egress enforcement point | Restricted pod security; non-root UID, read-only root filesystem, no privilege escalation/capabilities/host namespaces/mounts, runtime-default seccomp, hard CPU/memory/PID/ephemeral-storage limits, and default-deny ingress/egress NetworkPolicies enforced by the installed CNI. |
| Dedicated microVM | Dedicated KVM-capable hosts and isolated runner service that creates and destroys a fresh VM per run; pinned VMM and guest image | No shared writable disks or snapshots across tenants; minimal read-only guest image, bounded vCPU/RAM/disk/time, deny network by default, restricted VMM API and vsock, and host-side kill/cleanup verification. |

The contract's `BACKEND_REQUIRED_GATES` names the signed evidence items for each
class: WASM/WASI gates cover runtime/ABI pinning, capability imports, ambient
filesystem/process/clock/randomness denial, resource bounds, network denial,
cancellation, and cleanup; Kubernetes gates separately cover pool/runtime
identity, host/pod restrictions, CPU/memory/PID/disk quotas, enforced network
policy, metadata blocking, cancellation, and cleanup; microVM gates cover
KVM/VMM/guest identity, a fresh VM and private writable storage per run, a
minimal read-only guest, quotas, network denial, restricted VMM/vsock, and
cleanup. These names are a checklist contract, not deployment manifests or
proof that controls are present. The actual runtime, CNI, host kernel, and VMM
configuration must be selected and tested in the operator's environment.
Network policy at the Kubernetes API alone is insufficient if the selected CNI
does not enforce it.

### Rollout sequence for the full portfolio

1. Implement and threat-review a backend-neutral run contract, artifact
   attestation, admission decision, and audit event format. It must include an
   explicit backend and digest and reject requests if that backend is disabled.
2. Provision each backend as an independently disabled pool. Add a preflight
   probe and adversarial conformance suite for every backend; a passing suite
   for one backend never enables another.
3. Validate WASM/WASI, sandboxed Kubernetes, and microVM separately in staging
   using malicious test artifacts, egress tests, quotas, cancellation, cleanup,
   and cross-tenant tests.
4. Enable one explicitly selected backend only after its operator-owned gates
   pass. Keep the other two disabled until their own evidence is approved; do
   not implement silent fallback.
5. Add paid access only after per-backend usage metering, spend ceilings,
   cancellation/refund handling, and settlement reconciliation are reviewed.

No cost or capacity estimate is included: those require the selected cloud/host
prices, workload mix, runtime overhead, and expected concurrency.

## Implemented contract foundation (not an execution runtime)

`src/agent_marketplace/runtime_contract.py` now defines strict, immutable
backend-neutral shapes for artifact-attestation claims, backend readiness,
run admission requests/decisions, and metadata-only audit events. Its pure
admission function requires an exact backend, digest, agent/version, approved
review state, and enabled/conformant readiness for that same backend. Backend
readiness is an Ed25519-signed, time-bounded operator assertion bound to the
backend, exact environment/pool ID, monotonic readiness generation, policy
revision, enabled state, per-gate evidence digests, and trusted key lifecycle.
Admission requires both the requested pool ID and current operator-supplied
generation to match, preventing readiness evidence from being replayed across
staging/production, separate backend pools, or superseded readiness states. Each backend has a distinct
required gate set; admission also requires bounded canonical JSON reports and
the underlying source-evidence bytes. It recomputes the signed report digest and
each report's source-evidence digest. Reports must say `passed` and match the
exact gate, backend, pool, and policy revision; they must be timezone-aware, no
more than 24 hours old, and not future-dated. Missing, extra, malformed,
oversized, stale, or mismatched evidence fails closed. This validates report
shape, identity, and byte integrity, not whether source evidence semantically
proves the control; assessors must independently interpret that evidence. Readiness is dual-signed: an
independent conformance assessor signs the gate evidence digests, then a distinct
operator signs the enablement assertion. The assertion validity window is capped
at 24 hours, in addition to each signer's key lifecycle. Admission verifies them
using separate assessor, readiness-operator, and artifact-review trust sets;
assessor and readiness signer identities and key IDs must differ, and their
Ed25519 public keys must be cryptographically distinct. The artifact-review
signing key and signer identity must also be distinct from both readiness roles;
separate trust-set labels alone do not establish key or organizational separation. Unsigned, expired,
future-dated, mismatched, or revoked-key assertions fail closed. It rejects resource-limit overruns and never selects a fallback. Contract tests
cover mismatches, unavailable backends, bounds, and rejection of unknown
fields.

The module verifies Ed25519 signatures over a canonical, timezone-aware
attestation payload using operator-supplied trusted-key records. Each record
binds key ID and signer identity to a PEM public key, validity interval, and
optional key-revocation instant. The
admission policy itself requires this signature verification as well as a
trusted review approval and readiness record, and emits a distinct denial for
an invalid signature. It requires size-limited artifact bytes matching the
signed SHA-256 digest and rejects an explicitly revoked artifact before review
or signature checks. Artifact attestations must also be no more than 90 days
old by default (configurable by the admission caller); callers should set a
shorter bound where their review and revocation process supports it. This
limits replay of stale review claims but does not replace live revocation or
review-state checks. Revocation state still must come from a trusted control
plane source. This does not retrieve or store artifacts,
scan/quarantine them, or establish that review is current. Trusted-key records
define signer identity, a validity interval, and an optional revocation
instant; the verifier denies unknown, mismatched, expired, not-yet-valid, or
revoked keys, and rejects attestations timestamped outside the key's validity
window or in the future. The caller still owns secure key distribution, rotation, and
revocation state. This policy is not wired into an API, scheduler, artifact store,
review-state source. `src/agent_marketplace/audit_ledger.py` adds a bounded,
tenant-partitioned Redis store for metadata-only audit events, with optimistic
concurrent appends, idempotent event IDs within the retained window (same-ID
retries return the original record; conflicting reuse is rejected), a five-minute
default bound on future event timestamps, fail-closed append when the retained
chain/head is invalid, and SHA-256 hash links plus a chain/head verifier. The stored
head anchors the first retained sequence and its predecessor digest, so the
verifier detects accidental retained-prefix loss as well as changes inside the
window. Legacy ledgers without this anchor are accepted using their current
oldest record and are upgraded on their next append. `create_checkpoint` can
sign the verified head with an Ed25519 operator key; the returned tenant-bound
checkpoint can be exported to a separately protected immutable store, and
`verify_checkpoint` validates its signer, key validity/revocation, tenant, and
signature; `matches_checkpoint` requires trusted-key records and verifies the
checkpoint's retained-window anchor consistency, signature, tenant binding,
signer/key lifecycle, and current Redis head before reporting a match. The ledger does not export or persist checkpoints itself. It is not
wired into runtime paths; Redis operators can rewrite both records and heads,
so without an externally retained checkpoint it is not immutable, tamper-proof,
or externally anchored. Retention keeps the latest configured window and the
head remains stored. No backend is
provisioned or enabled; all launch gates below remain in force.

## Proposed architecture (not implemented)

- **Control plane:** the API authenticates the caller, checks ownership/access,
  validates the published manifest version, enforces quotas, and creates a run
  record. It never imports, evaluates, or launches publisher code itself.
- **Artifact intake:** accept only immutable, digest-addressed artifacts through
  a quarantine pipeline. Build and scan outside the serving API. Store signed
  provenance and approval state separately from seller-editable catalog data.
  Publication pins a reviewed digest; changing bytes requires a new version and
  review.
- **Scheduler:** enqueue a bounded run request containing an artifact digest,
  validated input, a short-lived run identity, and an explicit policy. Do not
  put long-lived credentials or unrestricted storage locations in task payloads.
- **Execution plane:** isolated workers in a separate account/cluster/host pool
  from the API and regular Celery workers. Use a per-run sandbox with an
  unprivileged identity, read-only base filesystem, minimal writable scratch,
  dropped capabilities, syscall restrictions, no host mounts, no shared
  service credentials, and enforced resource ceilings. A regular container
  alone is not an adequate multi-tenant boundary for untrusted code.
- **Network:** deny egress by default at the host/network layer. If a use case
  requires web access, route it through a policy-enforcing proxy that resolves
  and pins public addresses, checks every redirect, applies per-request/domain
  budgets, and blocks internal/control-plane destinations. Do not let the guest
  choose a proxy or bypass the enforcement point.
- **Results:** cap stdout/stderr and result bytes; validate the returned JSON
  against the versioned output schema; label it untrusted; persist only with an
  explicit retention policy and tenant ownership. Record digests and status,
  not secrets or unrestricted payloads, in audit events.
- **Revocation:** stop accepting runs for suspended or revoked versions
  immediately; cancel queued runs and terminate active sandboxes within a
  documented maximum interval; retain minimal audit evidence.

The selected backend and its concrete technology are infrastructure decisions
that must be validated on the target deployment. This repository does not
currently provision any of these execution pools. Do not substitute `eval`,
subprocess execution in an API/worker container, Docker-in-Docker, or a
publisher-controlled image launched with ambient host credentials.

## Mandatory launch gates

Do not enable publisher code execution until all of these are verified in the
target environment:

- documented isolation boundary, threat review, and escape-response procedure
  for each enabled backend;
- each WASM/WASI, sandboxed-Kubernetes, and microVM backend independently passes
  its escape, cleanup, accounting, and policy conformance tests before it can be
  enabled; backend unavailability never permits downgrade;
- default-deny egress tested against DNS rebinding, redirects, IPv4/IPv6 private
  ranges, metadata endpoints, and proxy bypass attempts;
- enforced per-run CPU, memory, PID, wall-time, storage, input/output, and log
  ceilings with tests proving whole-sandbox termination;
- no secret or host-filesystem visibility from a malicious test agent;
- tenant-crossing, concurrent-run, cleanup, and revocation tests;
- immutable artifacts, signature/provenance verification, review workflow, and
  emergency kill switch;
- metering, maximum spend, billing reconciliation, retention, abuse reporting,
  and operational ownership approved before any paid listing is offered.

Until those gates are met, keep the runtime feature unavailable and continue to
use only the server-owned managed-agent allow-list. The current heuristic
`data-curator` is not an untrusted-code sandbox and its heuristic safety scores
are not a content-moderation guarantee.
