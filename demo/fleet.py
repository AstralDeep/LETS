"""The host side of the demo: drives a LETS warden through a fleet of agents.

This module is the "host application" in LETS terms. It owns durable operation
IDs, holds the bearer credential, and calls the runtime at the lifecycle seams —
issue a root lease, spawn a child, request a transition receipt, close a lease.
It never decides whether an action is allowed; it only reports what the warden
answered.

Denials are the point of the demo, so every call is funnelled through `_attempt`,
which turns a refusal into an ordinary result record carrying the runtime's own
error code. Nothing here invents a message: the strings the UI shows in red come
back over the wire.
"""

from __future__ import annotations

import itertools
import json
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from uuid import uuid4

import httpx
from lets.client import LETSClient, LETSClientError

from demo import policy as demo_policy
from demo.config import EXECUTOR_AUDIENCE, Settings

SECOND_NS = 1_000_000_000

# What LETSClient sends; matched here because the production profile supplies its
# own httpx client and would otherwise lose the header.
JSON_MEDIA_TYPE = "application/json"


def _production_client(settings: Settings) -> httpx.Client:
    """Build the mTLS + JWT transport for the production warden.

    Two details matter and both are easy to get wrong.

    The SSL context is constructed explicitly rather than passing
    ``verify=<ca path>`` and ``cert=(crt, key)`` to httpx. When ``verify`` is a
    path, httpx builds its own context from it and never loads ``cert``, so the
    client certificate is silently dropped and the warden closes the connection
    with no response. LETS guards against exactly this in its own client, whose
    comment reads "Build one SSL context so a CA path cannot bypass
    client-certificate loading."

    Authentication is an httpx auth flow rather than a token handed to
    LETSClient, because LETSClient freezes the Authorization header at
    construction and production JWTs expire in minutes.
    """

    import ssl

    from demo.identity import JWTAuth

    identity = settings.identity
    assert identity is not None  # guaranteed by Settings.is_production

    context = ssl.create_default_context(cafile=str(settings.ca_cert))
    context.load_cert_chain(str(settings.client_cert), str(settings.client_key))

    return httpx.Client(
        base_url=settings.base_url.rstrip("/") + "/",
        headers={"accept": JSON_MEDIA_TYPE},
        verify=context,
        auth=JWTAuth(
            seed_path=identity.seed_path,
            kid=identity.kid,
            issuer=identity.issuer,
            audience=identity.audience,
            subject=identity.subject,
            tenant_id=identity.tenant_id,
            scopes=identity.scopes,
        ),
        timeout=15.0,
        follow_redirects=False,
    )


@dataclass
class LeaseRecord:
    """What the host remembers about a lease it created.

    Deliberately excludes credentials, agent memory, and opaque state — the same
    boundary `lets.integrations.ReplicaAuthorizer` draws. The authoritative
    residual always comes from the warden, never from here.
    """

    lease_id: str
    subject_id: str
    parent_id: str | None
    depth: int
    allocation: list[int]
    capabilities: list[str]
    ttl_ns: int
    role: str


@dataclass
class Event:
    seq: int
    ok: bool
    action: str
    label: str
    code: str | None = None
    detail: str | None = None
    lease_id: str | None = None
    cost: list[int] | None = None
    ledger_unchanged: bool | None = None
    note: str | None = None


class Fleet:
    """A population of leases governed by one warden envelope."""

    def __init__(self, settings: Settings, *, registry_path: Path | None = None) -> None:
        self._settings = settings
        # The production node authenticates with short-lived JWTs over mutual
        # TLS, which needs a transport LETSClient cannot build from a token.
        self._httpx: httpx.Client | None = None
        if settings.is_production:
            self._httpx = _production_client(settings)
            self._client = LETSClient(settings.base_url, client=self._httpx,
                                      total_timeout_s=20.0)
        else:
            self._client = LETSClient(settings.base_url, token=settings.token, timeout=15.0,
                                      total_timeout_s=20.0)
        self._lock = threading.Lock()
        self._leases: dict[str, LeaseRecord] = {}
        self._events: list[Event] = []
        self._event_seq = itertools.count(1)
        self._names = itertools.count(1)
        self.policy_digest: str = ""
        # A lease outlives the process that created it. Without somewhere durable
        # to remember them, restarting this app would orphan every live lease --
        # their budget would stay escrowed with nothing left able to close them.
        self._registry_path = registry_path or settings.registry_path()

    # ---------------------------------------------------------------- lifecycle

    def start(self) -> None:
        """Register the demo policy. Content-addressed, so re-running is safe."""
        try:
            self._client.liveness()
        except Exception as exc:
            script = "run-prod.ps1" if self._settings.is_production else "run.ps1"
            raise SystemExit(
                f"Cannot reach the warden at {self._settings.base_url} ({exc.__class__.__name__}).\n"
                f"Start it first, or use scripts\\{script} which starts both."
            ) from exc

        registered = self._client.register_policy(demo_policy.POLICY.to_dict())
        self.policy_digest = registered["policy_digest"]
        if self.policy_digest != demo_policy.POLICY.digest:
            raise RuntimeError(
                "warden returned a different policy digest than we computed locally: "
                f"{self.policy_digest} != {demo_policy.POLICY.digest}"
            )
        self._restore()

    def close(self) -> None:
        self._client.close()
        # LETSClient only closes transports it created, so the production
        # profile's client is ours to clean up.
        if self._httpx is not None:
            self._httpx.close()

    # ------------------------------------------------------------- persistence

    def _restore(self) -> None:
        """Re-adopt leases created by an earlier run of this app.

        Only leases the warden still reports as live are kept; anything closed or
        expired is dropped so the tree does not show ghosts.
        """
        if not self._registry_path.exists():
            return
        try:
            saved = json.loads(self._registry_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return

        adopted = 0
        highest = 0
        for row in saved:
            try:
                record = LeaseRecord(**row)
            except TypeError:
                continue
            try:
                snapshot = self._client.lease(record.lease_id)
            except LETSClientError:
                continue
            if snapshot["status"] not in {"ACTIVE", "PROVISIONED", "QUIESCENT"}:
                continue
            self._leases[record.lease_id] = record
            adopted += 1
            suffix = record.subject_id.rsplit("-", 1)[-1]
            if suffix.isdigit():
                highest = max(highest, int(suffix))

        if adopted:
            # Keep generated names from colliding with the ones we just adopted.
            self._names = itertools.count(highest + 1)
            print(f"[demo] re-adopted {adopted} live lease(s) from a previous run")
        self._persist()

    def _persist(self) -> None:
        """Call with the lock held, after any change to `_leases`."""
        try:
            self._registry_path.write_text(
                json.dumps([asdict(r) for r in self._leases.values()], indent=1),
                encoding="utf-8",
            )
        except OSError:
            pass  # a demo should not die because it could not write a cache

    # ------------------------------------------------------------------ helpers

    def _next_name(self, stem: str) -> str:
        return f"{stem}-{next(self._names)}"

    def _record(self, event: Event) -> Event:
        self._events.append(event)
        del self._events[:-60]
        return event

    def _ledger_vectors(self) -> tuple[list[int], ...] | None:
        try:
            inv = self._client.invariants()
        except LETSClientError:
            return None
        return (
            list(inv["free_pool"]),
            list(inv["lease_residual"]),
            list(inv["consumed"]),
        )

    def _attempt(
        self,
        action: str,
        label: str,
        call: Callable[[], Mapping[str, Any]],
        *,
        cost: list[int] | None = None,
        on_success: Callable[[Mapping[str, Any]], str | None] | None = None,
        record: bool = True,
    ) -> Event:
        """Run one warden call, capturing a refusal as data rather than an error.

        The ledger is sampled either side of the call so the UI can state
        plainly that a denied action moved nothing. Pass ``record=False`` for
        calls made in bulk, so they do not flood the journal.
        """
        keep = self._record if record else (lambda event: event)
        before = self._ledger_vectors() if record else None
        try:
            result = call()
        except LETSClientError as exc:
            after = self._ledger_vectors() if record else None
            return keep(
                Event(
                    seq=next(self._event_seq),
                    ok=False,
                    action=action,
                    label=label,
                    code=exc.problem.code,
                    detail=exc.problem.detail,
                    ledger_unchanged=(before is not None and before == after),
                )
            )
        except ValueError as exc:
            # Client-side guards fire before anything reaches the network.
            return keep(
                Event(
                    seq=next(self._event_seq),
                    ok=False,
                    action=action,
                    label=label,
                    code="client_validation",
                    detail=str(exc),
                    ledger_unchanged=True,
                )
            )

        note = on_success(result) if on_success else None
        return keep(
            Event(
                seq=next(self._event_seq),
                ok=True,
                action=action,
                label=label,
                lease_id=result.get("lease_id"),
                cost=cost,
                note=note,
            )
        )

    # ------------------------------------------------------------------ actions

    def provision_root(self) -> Event:
        """Partition rights out of the warden free pool into a root lease."""
        with self._lock:
            if any(r.depth == 0 for r in self._leases.values()):
                return self._record(
                    Event(
                        seq=next(self._event_seq),
                        ok=False,
                        action="provision_root",
                        label="Provision root agent",
                        code="demo_precondition",
                        detail="a root agent already exists; reset to start over",
                        ledger_unchanged=True,
                    )
                )
            subject = "agent-root"
            allocation = list(demo_policy.ROOT_ALLOCATION)
            ttl_ns = demo_policy.ROOT_TTL_NS

            def register(result: Mapping[str, Any]) -> str:
                self._leases[result["lease_id"]] = LeaseRecord(
                    lease_id=result["lease_id"],
                    subject_id=subject,
                    parent_id=None,
                    depth=0,
                    allocation=allocation,
                    capabilities=list(demo_policy.ROOT_CAPABILITIES),
                    ttl_ns=ttl_ns,
                    role="root",
                )
                self._persist()
                return f"allocated {allocation} from the free pool"

            return self._attempt(
                "provision_root",
                f"Provision root agent {subject}",
                lambda: self._client.issue_root(
                    {
                        "request_id": uuid4().hex,
                        "tenant_id": self.tenant_id,
                        "envelope_id": self.envelope_id,
                        "subject_id": subject,
                        "allocation": allocation,
                        "capabilities": list(demo_policy.ROOT_CAPABILITIES),
                        "policy_digest": self.policy_digest,
                        "ttl_ns": ttl_ns,
                    }
                ),
                on_success=register,
            )

    def spawn_child(self, parent_id: str) -> Event:
        """Delegate a slice of a parent's remaining budget to a new agent."""
        with self._lock:
            parent = self._leases.get(parent_id)
            if parent is None:
                return self._unknown_lease("spawn_child", parent_id)
            residual = self._residual(parent_id)
            if residual is None:
                return self._unknown_lease("spawn_child", parent_id)

            # A quarter of what the parent has left, and never zero in every
            # dimension — LETS rejects cost-free authority outright.
            allocation = [max(1, value // 4) for value in residual]
            subject = self._next_name("worker")
            ttl_ns = max(SECOND_NS, parent.ttl_ns // 2)
            capabilities = list(parent.capabilities)

            def register(result: Mapping[str, Any]) -> str:
                self._leases[result["lease_id"]] = LeaseRecord(
                    lease_id=result["lease_id"],
                    subject_id=subject,
                    parent_id=parent_id,
                    depth=parent.depth + 1,
                    allocation=allocation,
                    capabilities=capabilities,
                    ttl_ns=ttl_ns,
                    role="worker",
                )
                self._persist()
                return f"escrowed {allocation} out of {parent.subject_id}"

            return self._attempt(
                "spawn_child",
                f"Spawn {subject} under {parent.subject_id}",
                lambda: self._client.spawn(
                    parent_id,
                    {
                        "request_id": uuid4().hex,
                        "subject_id": subject,
                        "allocation": allocation,
                        "capabilities": capabilities,
                        "ttl_ns": ttl_ns,
                    },
                ),
                on_success=register,
            )

    def spawn_oversized(self, parent_id: str) -> Event:
        """Ask for more than the parent holds. Must be refused."""
        with self._lock:
            parent = self._leases.get(parent_id)
            if parent is None:
                return self._unknown_lease("spawn_oversized", parent_id)
            residual = self._residual(parent_id)
            if residual is None:
                return self._unknown_lease("spawn_oversized", parent_id)

            allocation = [value * 2 + 1000 for value in residual]
            subject = self._next_name("greedy")
            return self._attempt(
                "spawn_oversized",
                f"Spawn {subject} demanding {allocation} (parent holds {residual})",
                lambda: self._client.spawn(
                    parent_id,
                    {
                        "request_id": uuid4().hex,
                        "subject_id": subject,
                        "allocation": allocation,
                        "capabilities": list(parent.capabilities),
                        "ttl_ns": max(SECOND_NS, parent.ttl_ns // 2),
                    },
                ),
            )

    def spawn_escalated(self, parent_id: str) -> Event:
        """Ask for a capability the parent never held. Must be refused.

        The allocation is deliberately modest and affordable so the capability is
        the only thing wrong with the request.
        """
        with self._lock:
            parent = self._leases.get(parent_id)
            if parent is None:
                return self._unknown_lease("spawn_escalated", parent_id)
            residual = self._residual(parent_id)
            if residual is None:
                return self._unknown_lease("spawn_escalated", parent_id)

            allocation = [max(1, value // 8) for value in residual]
            requested = sorted({*parent.capabilities, demo_policy.WITHHELD_CAPABILITY})
            subject = self._next_name("escalator")
            return self._attempt(
                "spawn_escalated",
                f"Spawn {subject} requesting '{demo_policy.WITHHELD_CAPABILITY}'",
                lambda: self._client.spawn(
                    parent_id,
                    {
                        "request_id": uuid4().hex,
                        "subject_id": subject,
                        "allocation": allocation,
                        "capabilities": requested,
                        "ttl_ns": max(SECOND_NS, parent.ttl_ns // 2),
                    },
                ),
            )

    def do_work(self, lease_id: str, transition: str, *, journal: bool = True) -> Event:
        """Request a receipt for one protected effect. Debits the residual."""
        with self._lock:
            record = self._leases.get(lease_id)
            if record is None:
                return self._unknown_lease("do_work", lease_id)
            cost = demo_policy.TRANSITION_COSTS.get(transition)
            return self._attempt(
                "do_work",
                f"{record.subject_id} performs '{transition}' (cost {cost})",
                lambda: self._client.authorize(
                    lease_id,
                    {
                        "request_id": uuid4().hex,
                        "transition": transition,
                        # The wire field is `executor_audience`; the client
                        # rejects the internal name `audience` outright.
                        "executor_audience": EXECUTOR_AUDIENCE,
                        "nonce": uuid4().hex,
                    },
                ),
                cost=cost,
                on_success=lambda r: f"receipt {r['receipt_id'][:20]}… seq {r['resulting_sequence']}",
                record=journal,
            )

    def drain(self, lease_id: str, transition: str = "research", limit: int = 400) -> list[Event]:
        """Work an agent until the warden stops it. Proves the budget is real.

        The individual transitions are kept out of the journal — a few hundred
        identical `allow` rows would bury the one line that matters, which is the
        refusal at the end.
        """
        events: list[Event] = []
        for _ in range(limit):
            event = self.do_work(lease_id, transition, journal=False)
            events.append(event)
            if not event.ok:
                break
        else:
            events.append(
                Event(
                    seq=next(self._event_seq),
                    ok=False,
                    action="drain",
                    label=f"stopped after {limit} transitions",
                    code="demo_limit",
                    detail="demo safety limit reached before the budget ran out",
                    ledger_unchanged=True,
                )
            )

        allowed = sum(1 for e in events if e.ok)
        final = events[-1]
        with self._lock:
            record = self._leases.get(lease_id)
            name = record.subject_id if record else lease_id
            self._record(
                Event(
                    seq=next(self._event_seq),
                    ok=False,
                    action="drain",
                    label=(
                        f"{name} repeated '{transition}' until the warden refused"
                        f" — {allowed} authorized, then stopped"
                    ),
                    code=final.code,
                    detail=final.detail,
                    ledger_unchanged=final.ledger_unchanged,
                )
            )
        return events

    def reset(self) -> Event:
        """Close every lease deepest-first, then reclaim."""
        with self._lock:
            ordered = sorted(self._leases.values(), key=lambda r: r.depth, reverse=True)
            closed = 0
            failures: list[str] = []
            for record in ordered:
                try:
                    self._client.close_lease(record.lease_id, {"request_id": uuid4().hex})
                    closed += 1
                except LETSClientError as exc:
                    failures.append(f"{record.subject_id}: {exc.problem.code}")
            try:
                self._client.reclaim({})
            except LETSClientError as exc:
                failures.append(f"reclaim: {exc.problem.code}")
            self._leases.clear()
            self._events.clear()
            self._persist()
            return self._record(
                Event(
                    seq=next(self._event_seq),
                    ok=not failures,
                    action="reset",
                    label=f"Closed {closed} lease(s) and reclaimed",
                    code=None if not failures else "partial_reset",
                    detail=None if not failures else "; ".join(failures),
                )
            )

    # -------------------------------------------------------------------- state

    def _unknown_lease(self, action: str, lease_id: str) -> Event:
        return self._record(
            Event(
                seq=next(self._event_seq),
                ok=False,
                action=action,
                label="Unknown lease",
                code="demo_precondition",
                detail=f"{lease_id} is not tracked by this demo",
                ledger_unchanged=True,
            )
        )

    def _residual(self, lease_id: str) -> list[int] | None:
        try:
            return list(self._client.lease(lease_id)["residual"])
        except LETSClientError:
            return None

    @property
    def tenant_id(self) -> str:
        return self._info()["metadata"]["tenant_id"]

    @property
    def envelope_id(self) -> str:
        return self._info()["metadata"]["envelope_id"]

    def _info(self) -> Mapping[str, Any]:
        if not hasattr(self, "_cached_info"):
            self._cached_info = self._client.info()
        return self._cached_info

    def snapshot(self) -> dict[str, Any]:
        """Everything the dashboard renders, in one payload."""
        info = self._info()
        invariants = self._client.invariants()

        leases = []
        for record in sorted(self._leases.values(), key=lambda r: (r.depth, r.subject_id)):
            try:
                snap = self._client.lease(record.lease_id)
            except LETSClientError:
                continue
            grant = snap["grant"]
            leases.append(
                {
                    "lease_id": record.lease_id,
                    "subject_id": record.subject_id,
                    "parent_id": record.parent_id,
                    "depth": record.depth,
                    "role": record.role,
                    "allocation": list(grant["allocation"]),
                    "residual": list(snap["residual"]),
                    "capabilities": list(grant["capabilities"]),
                    "status": snap["status"],
                    "current_state": snap["current_state"],
                    "sequence": snap["sequence"],
                }
            )

        return {
            "envelope": {
                "warden_id": info["warden_id"],
                "protocol": info["protocol"],
                "tenant_id": info["metadata"]["tenant_id"],
                "envelope_id": info["metadata"]["envelope_id"],
                "config_epoch": info["metadata"]["config_epoch"],
            },
            "policy": {
                "policy_id": demo_policy.POLICY.policy_id,
                "digest": self.policy_digest,
                "transitions": [
                    {
                        "name": name,
                        "cost": cost,
                        "capability": demo_policy.TRANSITION_CAPABILITIES[name],
                    }
                    for name, cost in demo_policy.TRANSITION_COSTS.items()
                ],
            },
            "dimensions": demo_policy.dimension_labels(),
            "leases": leases,
            "ledger": _ledger(invariants),
            "events": [vars(e) for e in reversed(self._events)],
        }


def _ledger(invariants: Mapping[str, Any]) -> dict[str, Any]:
    """Re-derive the conservation equation instead of trusting `healthy`.

    LETS states the invariant as:

        initial local share + accepted transfers
            = free pool + live lease residuals + consumed + sent transfers

    Checking it here, componentwise, is the whole point of the ledger panel. If
    this only echoed the warden's own `healthy` flag it would be a status light
    grading its own homework.
    """
    initial = list(invariants["initial_share"])
    in_ = list(invariants["transferred_in"])
    out = list(invariants["transferred_out"])
    free = list(invariants["free_pool"])
    residual = list(invariants["lease_residual"])
    consumed = list(invariants["consumed"])

    rows = []
    balanced = True
    for i in range(len(initial)):
        lhs = free[i] + residual[i] + consumed[i] + out[i]
        rhs = initial[i] + in_[i]
        ok = lhs == rhs
        balanced = balanced and ok
        rows.append(
            {
                "index": i,
                "free_pool": free[i],
                "lease_residual": residual[i],
                "consumed": consumed[i],
                "transferred_out": out[i],
                "lhs": lhs,
                "rhs": rhs,
                "balanced": ok,
            }
        )

    return {
        "initial_share": initial,
        "free_pool": free,
        "lease_residual": residual,
        "consumed": consumed,
        "transferred_in": in_,
        "transferred_out": out,
        "rows": rows,
        "balanced": balanced,
        "warden_healthy": bool(invariants["healthy"]),
    }
