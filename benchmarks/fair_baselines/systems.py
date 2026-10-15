"""The five authority systems E1 compares, each exposing one `take(request_id)` attempt plus the
peer-side handlers site_agent.py routes to them: a durable central counter, static per-site
quotas, a pysyncobj Raft counter, and the real LETS warden with reactive cross-warden transfers,
alongside the independent actuator-side EffectLog used for the safety check.
"""

from __future__ import annotations

import base64
import json
import secrets
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pysyncobj import FAIL_REASON, SyncObj, SyncObjConf, SyncObjConsumer, replicated
from pysyncobj.transport import TCPTransport

from benchmarks.fair_baselines.common import (
    CAPABILITY,
    ENVELOPE_ID,
    SITES,
    TENANT,
    canonical_bytes,
    mapping,
    peer_mac,
    sha256_hex,
    string,
)
from lets.clock import SystemClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.errors import LETSError
from lets.executor import ExecutorPolicy, ReceiptVerifier, SQLiteReceiptReplayStore
from lets.models import IdentityContext
from lets.policy import MachineSpec, PolicySpec, ResourceDimension, TransitionSpec
from lets.service import WardenService
from lets.storage import SQLiteStorage

EventSink = Callable[[str, str, int, str], None]


@dataclass(frozen=True, slots=True)
class Decision:
    authorized: bool
    reason: str
    retryable: bool
    messages: int = 0
    remaining: int | None = None


class PeerUnreachableError(RuntimeError):
    pass


class PeerRejectedError(RuntimeError):
    pass


class PeerTransport:
    def __init__(
        self,
        alias: str,
        token: str,
        peer_urls: Mapping[str, str],
        timeout_s: float,
    ) -> None:
        self.alias = alias
        self.token = token
        self.peer_urls = dict(peer_urls)
        self.timeout_s = timeout_s

    def post(self, peer: str, path: str, payload: Mapping[str, object]) -> dict[str, Any]:
        body = canonical_bytes(payload)
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(32)
        body_sha256 = sha256_hex(body)
        signature = peer_mac(self.token, path, timestamp, nonce, body_sha256, self.alias)
        request = urllib.request.Request(
            f"{self.peer_urls[peer]}{path}",
            data=body,
            headers={
                "Authorization": f"LETS-HMAC {signature}",
                "Content-Type": "application/json",
                "X-LETS-Peer-Alias": self.alias,
                "X-LETS-Timestamp": timestamp,
                "X-LETS-Nonce": nonce,
                "X-LETS-Body-SHA256": body_sha256,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                return mapping(json.loads(response.read()), "peer response")
        except urllib.error.HTTPError as exc:
            detail = exc.read()
            try:
                reason = str(mapping(json.loads(detail), "peer error").get("error", "rejected"))
            except (ValueError, json.JSONDecodeError):
                reason = "rejected"
            raise PeerRejectedError(reason) from None
        except (OSError, urllib.error.URLError, TimeoutError):
            raise PeerUnreachableError(peer) from None


class MessageCounter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    def add(self, count: int = 1) -> None:
        with self._lock:
            self._count += count

    @property
    def value(self) -> int:
        with self._lock:
            return self._count


class DurableCounter:
    def __init__(self, path: Path, budget: int) -> None:
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS counter(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
            "remaining INTEGER NOT NULL CHECK(remaining >= 0), consumed INTEGER NOT NULL) STRICT"
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO counter(singleton, remaining, consumed) VALUES(1, ?, 0)",
            (budget,),
        )
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS requests(request_id TEXT PRIMARY KEY, site TEXT NOT NULL, "
            "outcome TEXT NOT NULL) STRICT"
        )

    def take(self, request_id: str, site: str) -> tuple[bool, int]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                prior = self._connection.execute(
                    "SELECT outcome FROM requests WHERE request_id=?", (request_id,)
                ).fetchone()
                if prior is None:
                    remaining = int(
                        self._connection.execute(
                            "SELECT remaining FROM counter WHERE singleton=1"
                        ).fetchone()[0]
                    )
                    outcome = "authorized" if remaining > 0 else "exhausted"
                    if remaining > 0:
                        self._connection.execute(
                            "UPDATE counter SET remaining=remaining-1, consumed=consumed+1 "
                            "WHERE singleton=1"
                        )
                    self._connection.execute(
                        "INSERT INTO requests(request_id, site, outcome) VALUES(?, ?, ?)",
                        (request_id, site, outcome),
                    )
                else:
                    outcome = str(prior[0])
                self._connection.execute("COMMIT")
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            remaining = self.remaining()
        return outcome == "authorized", remaining

    def remaining(self) -> int:
        row = self._connection.execute("SELECT remaining FROM counter WHERE singleton=1").fetchone()
        return int(row[0])

    def consumed(self) -> int:
        row = self._connection.execute("SELECT consumed FROM counter WHERE singleton=1").fetchone()
        return int(row[0])

    def close(self) -> None:
        self._connection.close()


class CentralCounterSystem:
    kind = "central"

    def __init__(
        self,
        name: str,
        site: str,
        host: str,
        state_dir: Path,
        budget: int,
        transport: PeerTransport,
        events: EventSink,
    ) -> None:
        self.name = name
        self.site = site
        self.host = host
        self.messages = MessageCounter()
        self._transport = transport
        self._events = events
        self._counter = (
            DurableCounter(state_dir / f"{name}.sqlite3", budget) if site == host else None
        )

    @property
    def hosts_pool(self) -> bool:
        return self._counter is not None

    def serve_take(self, request_id: str, source: str) -> dict[str, object]:
        if self._counter is None:
            raise ValueError("this site does not host the central counter")
        authorized, remaining = self._counter.take(request_id, source)
        self.messages.add()
        self._events(self.name, "free", remaining, source)
        return {"authorized": authorized, "remaining": remaining}

    def take(self, request_id: str) -> Decision:
        if self._counter is not None:
            authorized, remaining = self._counter.take(request_id, self.site)
            self._events(self.name, "free", remaining, self.site)
            return Decision(
                authorized, "authorized" if authorized else "exhausted", False, 0, remaining
            )
        self.messages.add()
        try:
            response = self._transport.post(
                self.host, f"/peer/central/{self.name}/take", {"request_id": request_id}
            )
        except PeerUnreachableError:
            return Decision(False, "unreachable", True, 1)
        except PeerRejectedError as exc:
            return Decision(False, f"rejected:{exc}", True, 1)
        authorized = response.get("authorized") is True
        remaining = response.get("remaining")
        return Decision(
            authorized,
            "authorized" if authorized else "exhausted",
            False,
            1,
            remaining if isinstance(remaining, int) else None,
        )

    def usable_units(self) -> int | None:
        return self._counter.remaining() if self._counter is not None else None

    def snapshot(self) -> dict[str, object]:
        return {
            "system": self.name,
            "kind": self.kind,
            "host": self.host,
            "remaining": self.usable_units(),
            "consumed": self._counter.consumed() if self._counter is not None else None,
            "messages": self.messages.value,
        }

    def start(self) -> None:
        return None

    def close(self) -> None:
        if self._counter is not None:
            self._counter.close()


class StaticQuotaSystem:
    kind = "static-quota"

    def __init__(
        self, name: str, site: str, state_dir: Path, share: int, events: EventSink
    ) -> None:
        self.name = name
        self.site = site
        self.share = share
        self.messages = MessageCounter()
        self._events = events
        self._counter = DurableCounter(state_dir / f"{name}.sqlite3", share)

    def take(self, request_id: str) -> Decision:
        authorized, remaining = self._counter.take(request_id, self.site)
        self._events(self.name, "free", remaining, self.site)
        return Decision(
            authorized, "authorized" if authorized else "exhausted", False, 0, remaining
        )

    def usable_units(self) -> int | None:
        return self._counter.remaining()

    def snapshot(self) -> dict[str, object]:
        return {
            "system": self.name,
            "kind": self.kind,
            "share": self.share,
            "remaining": self._counter.remaining(),
            "consumed": self._counter.consumed(),
            "messages": self.messages.value,
        }

    def start(self) -> None:
        return None

    def close(self) -> None:
        self._counter.close()


class BudgetStateMachine(SyncObjConsumer):
    def __init__(self, budget: int) -> None:
        super().__init__()
        self.__remaining = budget
        self.__decisions: dict[str, bool] = {}

    @replicated
    def take(self, request_id: str) -> tuple[bool, int]:
        if request_id not in self.__decisions:
            granted = self.__remaining > 0
            if granted:
                self.__remaining -= 1
            self.__decisions[request_id] = granted
        return self.__decisions[request_id], self.__remaining

    def remaining(self) -> int:
        return self.__remaining

    def consumed(self) -> int:
        return sum(1 for granted in self.__decisions.values() if granted)


def counting_transport(counter: MessageCounter) -> type[TCPTransport]:
    class CountingTransport(TCPTransport):
        def send(self, node: Any, message: Any) -> bool:
            counter.add()
            return bool(super().send(node, message))

    return CountingTransport


class RaftCounterSystem:
    kind = "raft-quorum"

    def __init__(
        self,
        name: str,
        site: str,
        state_dir: Path,
        budget: int,
        self_address: str,
        peer_addresses: Mapping[str, str],
        timeout_s: float,
        events: EventSink,
    ) -> None:
        self.name = name
        self.site = site
        self.messages = MessageCounter()
        self.timeout_s = timeout_s
        self._events = events
        self._machine = BudgetStateMachine(budget)
        conf = SyncObjConf(
            autoTick=False,
            journalFile=str(state_dir / f"{name}.journal"),
            fullDumpFile=str(state_dir / f"{name}.dump"),
            appendEntriesUseBatch=True,
            commandsWaitLeader=True,
            onStateChanged=self._on_state_changed,
        )
        self._node = SyncObj(
            self_address,
            list(peer_addresses.values()),
            conf=conf,
            consumers=[self._machine],
            transportClass=counting_transport(self.messages),
        )
        self._stop = threading.Event()
        # pysyncobj's own tick thread exits with the thread that built the node, so tick here
        self._ticker = threading.Thread(target=self._tick_loop, name=f"{name}-tick", daemon=True)
        self._ticker.start()

    def _tick_loop(self) -> None:
        while not self._stop.is_set():
            self._node.doTick(0.05)

    def _on_state_changed(self, old_state: int, new_state: int) -> None:
        self._events(self.name, "raft_state", int(new_state), f"from {int(old_state)}")

    def ready(self) -> bool:
        return self._node.getStatus().get("leader") is not None

    def take(self, request_id: str) -> Decision:
        try:
            granted, remaining = self._machine.take(request_id, sync=True, timeout=self.timeout_s)
        except Exception as exc:
            code = getattr(exc, "errorCode", str(exc))
            reason = {
                FAIL_REASON.MISSING_LEADER: "no_leader",
                FAIL_REASON.QUEUE_FULL: "queue_full",
                FAIL_REASON.DISCARDED: "discarded",
                FAIL_REASON.NOT_LEADER: "not_leader",
                FAIL_REASON.LEADER_CHANGED: "leader_changed",
                FAIL_REASON.REQUEST_DENIED: "request_denied",
                FAIL_REASON.UNKNOWN_OUTCOME: "unknown_outcome",
            }.get(code, f"timeout:{code}")
            return Decision(False, reason, True, 0)
        self._events(self.name, "free", int(remaining), self.site)
        return Decision(
            bool(granted), "authorized" if granted else "exhausted", False, 0, int(remaining)
        )

    def usable_units(self) -> int | None:
        return self._machine.remaining()

    def snapshot(self) -> dict[str, object]:
        status = self._node.getStatus()
        return {
            "system": self.name,
            "kind": self.kind,
            "remaining": self._machine.remaining(),
            "consumed": self._machine.consumed(),
            "messages": self.messages.value,
            "raft_state": int(status.get("state", -1)),
            "raft_term": int(status.get("raft_term", -1)),
            "raft_leader": str(status.get("leader")),
            "raft_has_quorum": bool(status.get("has_quorum")),
        }

    def start(self) -> None:
        return None

    def close(self) -> None:
        self._stop.set()
        self._ticker.join(timeout=5)
        self._node.destroy()


def experiment_policy() -> PolicySpec:
    return PolicySpec(
        policy_id="fair-baselines-policy",
        policy_version="v1",
        dimensions=(ResourceDimension("actions", "count"),),
        machine=MachineSpec(
            machine_id="fair-baselines-worker",
            initial_state="ready",
            transitions=(TransitionSpec("act", "ready", "ready", (1,), CAPABILITY),),
        ),
        max_lease_ttl_ns=3_600_000_000_000,
        receipt_ttl_ns=300_000_000_000,
        max_clock_uncertainty_ns=0,
        transfer_gap_window=64,
    )


class LetsSystem:
    kind = "lets"

    def __init__(
        self,
        name: str,
        site: str,
        state_dir: Path,
        budget: int,
        share: int,
        seed: bytes,
        public_keys: Mapping[str, tuple[str, bytes]],
        transport: PeerTransport,
        events: EventSink,
        seek_interval_s: float = 0.5,
    ) -> None:
        self.name = name
        self.site = site
        self.share = share
        self.messages = MessageCounter()
        self._transport = transport
        self._events = events
        self._seek_interval_s = seek_interval_s
        self._lock = threading.RLock()
        self._clock = SystemClock()
        self._policy = experiment_policy()
        self._registry = PublicKeyRegistry(clock=self._clock)
        for warden_id, (key_id, public_key) in sorted(public_keys.items()):
            self._registry.register(warden_id, key_id, public_key)
        self._signer = Ed25519Signer.from_seed(site, seed)
        self._store = SQLiteStorage.initialize(
            state_dir / f"{name}-warden.sqlite3",
            site,
            (budget,),
            signing_key_id=self._signer.key_id,
            signing_public_key=self._signer.public_key_bytes,
            tenant_id=TENANT,
            envelope_id=ENVELOPE_ID,
            initial_local_share=(share,),
            receipt_ttl_ns=self._policy.receipt_ttl_ns,
            max_clock_uncertainty_ns=0,
            transfer_gap_window=self._policy.transfer_gap_window,
        )
        self._peers = tuple(sorted(set(public_keys) - {site}))
        self._service = WardenService(
            self._store,
            signer=self._signer,
            clock=self._clock,
            trust_registry=self._registry,
            allowed_peer_wardens=set(self._peers),
        )
        self._service.register_policy(self._policy)
        self._replay = SQLiteReceiptReplayStore.initialize(
            state_dir / f"{name}-executor.sqlite3", allow_unanchored=True
        )
        self._verifier = ReceiptVerifier(
            self._registry,
            self._replay,
            ExecutorPolicy(
                audience=self.audience,
                tenant_id=TENANT,
                envelope_id=ENVELOPE_ID,
                config_epoch=1,
                allowed_policy_digests=frozenset({self._policy.digest}),
                allowed_machine_digests=frozenset({self._policy.machine.digest}),
                trusted_wardens=frozenset({site}),
            ),
            clock=self._clock,
        )
        self._identity = IdentityContext(
            site, TENANT, frozenset({"lets.admin", "lets.transfer", "lets.peer"}), "experiment"
        )
        self._lease_id: str | None = None
        self._sequence = 0
        self._residual = 0
        self._pool = share
        self._operation = 0
        self._lease_count = 0
        self._transfer_count: dict[str, int] = dict.fromkeys(self._peers, 0)
        self._outstanding: dict[str, dict[str, Any]] = {}
        self._pending_acks: dict[str, dict[str, Any]] = {}
        self._peer_backoff_until: dict[str, float] = dict.fromkeys(self._peers, 0.0)
        self._waiting = 0
        self._stop = threading.Event()
        self._seeker: threading.Thread | None = None
        self.transfers_in = 0
        self.transfers_out = 0
        self._reissue("initial")

    @property
    def audience(self) -> str:
        return f"fair-baselines-executor-{self.site}"

    def _close_lease(self, suffix: str) -> None:
        with self._lock:
            if self._lease_id is None:
                return
            self._service.close(
                request_id=f"close-{self.site}-{self._lease_count}-{suffix}",
                identity=self._identity,
                lease_id=self._lease_id,
                expected_sequence=self._sequence,
            )
            self._pool += self._residual
            self._lease_id = None
            self._residual = 0
            self._sequence = 0

    def _reissue(self, suffix: str) -> None:
        with self._lock:
            self._close_lease(suffix)
            if self._pool <= 0:
                return
            self._lease_count += 1
            grant = self._service.issue_root(
                request_id=f"issue-{self.site}-{self._lease_count}-{suffix}",
                identity=self._identity,
                tenant_id=TENANT,
                envelope_id=ENVELOPE_ID,
                subject_id=f"{self.site}-worker",
                allocation=(self._pool,),
                capabilities={CAPABILITY},
                policy_digest=self._policy.digest,
                ttl_ns=3_000_000_000_000,
            )
            self._lease_id = grant.lease_id
            self._residual = self._pool
            self._pool = 0
            self._sequence = 0

    def take(self, request_id: str) -> Decision:
        with self._lock:
            if self._lease_id is None or self._residual <= 0:
                return Decision(False, "exhausted_local", True, 0, self.usable_units())
            self._operation += 1
            try:
                receipt = self._service.authorize(
                    request_id=request_id,
                    identity=self._identity,
                    lease_id=self._lease_id,
                    transition="act",
                    audience=self.audience,
                    nonce=f"fair-baselines-{self.site}-{self._operation:016d}",
                    expected_state="ready",
                    expected_sequence=self._sequence,
                )
                self._verifier.verify_and_claim(receipt)
            except LETSError as exc:
                return Decision(False, exc.code, False, 0, self.usable_units())
            self._sequence = receipt.resulting_sequence
            self._residual -= 1
            remaining = self.usable_units()
            self._events(self.name, "free", remaining, self.site)
            return Decision(True, "authorized_and_claimed", False, 0, remaining)

    def usable_units(self) -> int:
        with self._lock:
            return self._pool + self._residual

    def set_waiting(self, waiting: int) -> None:
        with self._lock:
            self._waiting = waiting

    def start(self) -> None:
        self._seeker = threading.Thread(
            target=self._seek_loop, name=f"{self.name}-seeker", daemon=True
        )
        self._seeker.start()

    def _seek_loop(self) -> None:
        while not self._stop.wait(self._seek_interval_s):
            self._flush_pending_acks()
            with self._lock:
                need = self._waiting if self._residual <= 0 and self._pool <= 0 else 0
            if need <= 0:
                continue
            for peer in self._peers:
                if self._request_transfer(peer, need):
                    break

    def _request_transfer(self, peer: str, amount: int) -> bool:
        if time.monotonic() < self._peer_backoff_until[peer]:
            return False
        self.messages.add()
        try:
            response = self._transport.post(
                peer, f"/peer/lets/{self.name}/request-transfer", {"amount": amount}
            )
        except PeerUnreachableError:
            self._peer_backoff_until[peer] = time.monotonic() + 2.0
            return False
        except PeerRejectedError:
            self._peer_backoff_until[peer] = time.monotonic() + 2.0
            return False
        voucher = response.get("voucher")
        if not isinstance(voucher, Mapping):
            self._peer_backoff_until[peer] = time.monotonic() + 1.0
            return False
        self._accept(peer, dict(voucher))
        return True

    def _accept(self, peer: str, voucher: dict[str, Any]) -> None:
        with self._lock:
            ack = self._service.accept_transfer(identity=self._identity, voucher=voucher)
            amount = int(voucher["amount"][0])
            self._pool += amount
            self.transfers_in += 1
            self._events(self.name, "transfer_in", amount, peer)
            self._reissue(f"in-{self.transfers_in}")
            self._events(self.name, "free", self.usable_units(), self.site)
            self._pending_acks[peer] = ack.to_dict()
        self._flush_pending_acks()

    def _flush_pending_acks(self) -> None:
        with self._lock:
            pending = dict(self._pending_acks)
        for peer, ack in pending.items():
            self.messages.add()
            try:
                self._transport.post(peer, f"/peer/lets/{self.name}/finalize", {"ack": ack})
            except (PeerUnreachableError, PeerRejectedError):
                continue
            with self._lock:
                self._pending_acks.pop(peer, None)

    def serve_request_transfer(self, target: str, requested: int) -> dict[str, object]:
        if target not in self._peers:
            raise ValueError("unknown transfer target")
        self.messages.add()
        with self._lock:
            outstanding = self._outstanding.get(target)
            if outstanding is not None:
                return {"voucher": outstanding, "granted": int(outstanding["amount"][0])}
            available = self._pool + self._residual
            grant = min(requested, (available + 1) // 2)
            if grant <= 0:
                return {"voucher": None, "granted": 0}
            self._close_lease(f"out-{target}-{self._transfer_count[target]}")
            self._transfer_count[target] += 1
            voucher = self._service.prepare_transfer(
                request_id=f"xfer-{self.site}-{target}-{self._transfer_count[target]}",
                identity=self._identity,
                tenant_id=TENANT,
                envelope_id=ENVELOPE_ID,
                target_warden=target,
                amount=(grant,),
                policy_digest=self._policy.digest,
            )
            self._pool -= grant
            self._reissue(f"after-out-{target}-{self._transfer_count[target]}")
            self._events(self.name, "lease_reissue", self._pool + self._residual, target)
            payload = voucher.to_dict()
            self._outstanding[target] = payload
            self.transfers_out += 1
            self._events(self.name, "transfer_out", grant, target)
            self._events(self.name, "free", self.usable_units(), self.site)
            return {"voucher": payload, "granted": grant}

    def serve_finalize(self, source: str, ack: Mapping[str, Any]) -> dict[str, object]:
        self.messages.add()
        with self._lock:
            self._service.finalize_transfer(identity=self._identity, acknowledgement=ack)
            self._outstanding.pop(source, None)
        return {"finalized": True}

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            value = self._service.invariant_snapshot(identity=self._identity)
            replay = self._replay.status()
            return {
                "system": self.name,
                "kind": self.kind,
                "share": self.share,
                "initial_share": value.initial_share[0],
                "transferred_in": value.transferred_in[0],
                "transferred_out": value.transferred_out[0],
                "free_pool": value.free_pool[0],
                "lease_residual": value.lease_residual[0],
                "consumed": value.consumed[0],
                "healthy": value.healthy,
                "remaining": value.free_pool[0] + value.lease_residual[0],
                "transfers_in": self.transfers_in,
                "transfers_out": self.transfers_out,
                "outstanding_vouchers": len(self._outstanding),
                "pending_acks": len(self._pending_acks),
                "executor_claim_sequence": replay.claim_sequence,
                "messages": self.messages.value,
            }

    def close(self) -> None:
        self._stop.set()
        if self._seeker is not None:
            self._seeker.join(timeout=5)
        self._store.close()


class EffectLog:
    def __init__(self, path: Path, site: str) -> None:
        self.site = site
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA synchronous=FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS effects(system TEXT NOT NULL, request_id TEXT NOT NULL, "
            "site TEXT NOT NULL, effect_ns INTEGER NOT NULL, "
            "PRIMARY KEY(system, request_id)) STRICT"
        )

    def actuate(self, system: str, request_id: str, effect_ns: int) -> None:
        with self._lock:
            self._connection.execute(
                "INSERT INTO effects(system, request_id, site, effect_ns) VALUES(?, ?, ?, ?)",
                (system, request_id, self.site, effect_ns),
            )

    def summary(self) -> dict[str, dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT system, request_id FROM effects ORDER BY system, request_id"
            ).fetchall()
        result: dict[str, dict[str, object]] = {}
        for system, request_id in rows:
            entry = result.setdefault(system, {"count": 0, "request_ids": []})
            entry["count"] = int(entry["count"]) + 1
            ids = entry["request_ids"]
            assert isinstance(ids, list)
            ids.append(str(request_id))
        for entry in result.values():
            ids = entry["request_ids"]
            assert isinstance(ids, list)
            entry["sha256"] = sha256_hex("\n".join(ids).encode("utf-8"))
        return result

    def close(self) -> None:
        self._connection.close()


def public_key_table(value: object) -> dict[str, tuple[str, bytes]]:
    keys = mapping(value, "public_keys")
    table: dict[str, tuple[str, bytes]] = {}
    for warden_id, raw in keys.items():
        item = mapping(raw, f"public_keys[{warden_id!r}]")
        table[string(warden_id, "warden_id")] = (
            string(item.get("key_id"), "key_id"),
            base64.b64decode(string(item.get("public_key"), "public_key"), validate=True),
        )
    if set(table) != set(SITES):
        raise ValueError("public_keys must contain exactly s1, s2, and s3")
    return table


def peer_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def parse_peer_urls(value: object) -> dict[str, str]:
    peers = mapping(value, "peers")
    urls: dict[str, str] = {}
    for alias, raw in peers.items():
        url = string(raw, f"peers[{alias!r}]")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "http" or not parsed.hostname or parsed.port is None or parsed.path:
            raise ValueError(f"peers[{alias!r}] must be an origin-only http URL with a port")
        urls[string(alias, "peer alias")] = url
    return urls
