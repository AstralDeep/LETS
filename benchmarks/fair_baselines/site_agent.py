"""One process per site for E1: hosts every configured authority system (systems.py, including the
LETS delegation-tree, anchored, and stale-restore variants), replays the site's slice of the seeded
arrival plan (workload.py) with per-system retries into the independent effect log, and serves the
control API controller.py drives plus the HMAC peer API other sites call.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import shlex
import threading
import time
from collections.abc import Mapping
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from benchmarks.fair_baselines.common import (
    SCHEMA,
    SITE_ALIAS,
    RunConfig,
    SystemSpec,
    integer,
    mapping,
    peer_mac,
    site_alias,
    string,
)
from benchmarks.fair_baselines.systems import (
    AnchorSettings,
    CentralCounterSystem,
    Decision,
    EffectLog,
    LetsSystem,
    PeerRejectedError,
    PeerTransport,
    PeerUnreachableError,
    RaftCounterSystem,
    StaticQuotaSystem,
    parse_peer_urls,
    public_key_table,
)
from benchmarks.fair_baselines.workload import NS_PER_S, Arrival, arrival_plan, site_demand

MAX_BODY_BYTES = 4_000_000
PEER_CLOCK_SKEW_SECONDS = 30
PEER_NONCE_CACHE_LIMIT = 8192
LISTEN_BACKLOG = 128
AuthoritySystem = CentralCounterSystem | StaticQuotaSystem | RaftCounterSystem | LetsSystem


class AgentError(ValueError):
    pass


class Run:
    def __init__(
        self,
        site: str,
        config: RunConfig,
        state_dir: Path,
        transport: PeerTransport,
        seed: bytes,
        public_keys: Mapping[str, tuple[str, bytes]],
        raft_self: str | None,
        raft_peers: Mapping[str, str],
        anchor: AnchorSettings | None = None,
    ) -> None:
        self.site = site
        self.config = config
        self.state_dir = state_dir
        self.anchor = anchor
        self.plan: tuple[Arrival, ...] = arrival_plan(config)
        self.local_plan = tuple(arrival for arrival in self.plan if arrival.site == site)
        self.lock = threading.Lock()
        self.events: list[dict[str, object]] = []
        self.records: list[dict[str, object]] = []
        self.waiting: dict[str, int] = {}
        self.status = "configured"
        self.start_wall_ns: int | None = None
        self.start_mono_ns: int | None = None
        self.end_mono_ns: int | None = None
        self.outstanding = 0
        self.specs = {name: SystemSpec.parse(name) for name in config.systems}
        self.effects = EffectLog(state_dir / "effects.sqlite3", site)
        shares = config.shares
        self.systems: dict[str, AuthoritySystem] = {}
        try:
            self._build_systems(transport, seed, public_keys, raft_self, raft_peers, shares)
        except BaseException:
            self.close()
            raise

    def _build_systems(
        self,
        transport: PeerTransport,
        seed: bytes,
        public_keys: Mapping[str, tuple[str, bytes]],
        raft_self: str | None,
        raft_peers: Mapping[str, str],
        shares: Mapping[str, int],
    ) -> None:
        site = self.site
        config = self.config
        state_dir = self.state_dir
        for name, spec in self.specs.items():
            self.waiting[name] = 0
            if spec.kind == "central":
                assert spec.host is not None
                self.systems[name] = CentralCounterSystem(
                    name, site, spec.host, state_dir, config.envelope, transport, self.event
                )
            elif spec.kind == "static-quota":
                self.systems[name] = StaticQuotaSystem(
                    name, site, state_dir, shares[site], self.event
                )
            elif spec.kind == "raft-quorum":
                if raft_self is None or set(raft_peers) != set(config.sites) - {site}:
                    raise AgentError("raft-quorum requires raft addresses for every site")
                self.systems[name] = RaftCounterSystem(
                    name,
                    site,
                    state_dir,
                    config.envelope,
                    raft_self,
                    raft_peers,
                    config.raft_timeout_s,
                    self.event,
                )
            else:
                self.systems[name] = LetsSystem(
                    name,
                    site,
                    state_dir,
                    config.envelope,
                    shares[site],
                    seed,
                    public_keys,
                    transport,
                    self.event,
                    depth=spec.depth,
                    fanout=spec.fanout,
                    anchor=self._anchor_for(spec),
                )

    def _anchor_for(self, spec: SystemSpec) -> AnchorSettings | None:
        if not spec.anchored:
            return None
        if self.anchor is None:
            raise AgentError(f"{spec.name} needs an agent started with --anchor-root")
        return self.anchor

    def event(self, system: str, kind: str, value: int, detail: str) -> None:
        with self.lock:
            self.events.append(
                {
                    "system": system,
                    "site": self.site,
                    "mono_ns": time.monotonic_ns(),
                    "kind": kind,
                    "value": value,
                    "detail": detail,
                }
            )

    def ready(self) -> bool:
        return all(
            system.ready()
            for system in self.systems.values()
            if isinstance(system, RaftCounterSystem)
        )

    def start(self, start_at_epoch_ns: int) -> None:
        with self.lock:
            if self.status != "configured":
                raise AgentError(f"run is {self.status}, not configured")
            self.status = "starting"
        threading.Thread(target=self._launch, args=(start_at_epoch_ns,), daemon=True).start()

    def _launch(self, start_at_epoch_ns: int) -> None:
        for system in self.systems.values():
            system.start()
        delay = (start_at_epoch_ns - time.time_ns()) / NS_PER_S
        if delay > 0:
            time.sleep(delay)
        with self.lock:
            self.start_wall_ns = time.time_ns()
            self.start_mono_ns = time.monotonic_ns()
            self.status = "running"
            self.outstanding = len(self.local_plan) * len(self.systems)
        if self.outstanding == 0:
            self._finish()
            return
        for name in self.systems:
            threading.Thread(
                target=self._generate, args=(name,), name=f"gen-{name}", daemon=True
            ).start()
        for name, spec in self.specs.items():
            if spec.restore_site == self.site:
                threading.Thread(
                    target=self._restore, args=(name,), name=f"restore-{name}", daemon=True
                ).start()

    def _sleep_until(self, offset_s: float) -> None:
        assert self.start_mono_ns is not None
        wait = (self.start_mono_ns + int(offset_s * NS_PER_S) - time.monotonic_ns()) / NS_PER_S
        if wait > 0:
            time.sleep(wait)

    def _restore(self, name: str) -> None:
        system = self.systems[name]
        if not isinstance(system, LetsSystem):
            return
        snapshot_s, restore_s = self.config.restore_schedule_s
        try:
            self._sleep_until(snapshot_s)
            self.event(name, "restore_snapshot", system.usable_units(), system.take_snapshot())
            self._sleep_until(restore_s)
            accepted, detail = system.restore_snapshot()
            self.event(
                name,
                "restore_accepted" if accepted else "restore_refused",
                system.usable_units(),
                detail,
            )
        except Exception as exc:
            self.event(name, "restore_error", 0, f"{type(exc).__name__}: {exc}"[:240])

    def _generate(self, name: str) -> None:
        assert self.start_mono_ns is not None
        for arrival in self.local_plan:
            wait = (self.start_mono_ns + arrival.offset_ns - time.monotonic_ns()) / NS_PER_S
            if wait > 0:
                time.sleep(wait)
            threading.Thread(
                target=self._handle,
                args=(name, arrival),
                name=f"req-{name}-{arrival.request_id}",
                daemon=True,
            ).start()

    def _set_waiting(self, name: str, delta: int) -> None:
        with self.lock:
            self.waiting[name] += delta
            waiting = self.waiting[name]
        system = self.systems[name]
        if isinstance(system, LetsSystem):
            system.set_waiting(waiting)
        self.event(name, "waiting", waiting, self.site)

    def _handle(self, name: str, arrival: Arrival) -> None:
        system = self.systems[name]
        spec = self.specs[name]
        config = self.config
        rng = random.Random(f"{config.run_id}:{config.seed}:{name}:{arrival.index}")
        arrival_mono = time.monotonic_ns()
        deadline_mono = arrival_mono + int(config.deadline_s * NS_PER_S)
        attempts = 0
        messages = 0
        delay = config.retry_base_s
        outcome = "denied"
        reason = ""
        t_auth_ns: int | None = None
        remaining: int | None = None
        self._set_waiting(name, 1)
        try:
            while True:
                attempts += 1
                decision: Decision = system.take(arrival.request_id)
                messages += decision.messages
                reason = decision.reason
                remaining = decision.remaining
                if decision.authorized:
                    effect_ns = time.monotonic_ns()
                    self.effects.actuate(name, arrival.request_id, effect_ns)
                    outcome = "authorized"
                    t_auth_ns = effect_ns - arrival_mono
                    break
                if not (spec.retry and decision.retryable):
                    outcome = "denied"
                    break
                now = time.monotonic_ns()
                if now >= deadline_mono:
                    outcome = "timeout"
                    break
                pause = min(delay * rng.uniform(0.8, 1.2), (deadline_mono - now) / NS_PER_S)
                time.sleep(max(pause, 0.0))
                delay = min(delay * 1.5, config.retry_cap_s)
        finally:
            self._set_waiting(name, -1)
            assert self.start_mono_ns is not None
            record = {
                "system": name,
                "site": self.site,
                "index": arrival.index,
                "request_id": arrival.request_id,
                "planned_offset_ns": arrival.offset_ns,
                "arrival_offset_ns": arrival_mono - self.start_mono_ns,
                "outcome": outcome,
                "reason": reason,
                "t_auth_ns": t_auth_ns,
                "attempts": attempts,
                "messages": messages,
                "deadline_ns": int(config.deadline_s * NS_PER_S),
                "remaining_after": remaining,
            }
            with self.lock:
                self.records.append(record)
                self.outstanding -= 1
                finished = self.outstanding == 0
            if finished:
                self._finish()

    def _finish(self) -> None:
        with self.lock:
            self.end_mono_ns = time.monotonic_ns()
            self.status = "done"

    def progress(self) -> dict[str, object]:
        with self.lock:
            resolved: dict[str, int] = dict.fromkeys(self.systems, 0)
            for record in self.records:
                resolved[str(record["system"])] += 1
            elapsed = (
                None
                if self.start_mono_ns is None
                else (time.monotonic_ns() - self.start_mono_ns) / NS_PER_S
            )
            return {
                "status": self.status,
                "ready": self.ready(),
                "elapsed_s": elapsed,
                "planned_local_requests": len(self.local_plan),
                "resolved": resolved,
                "waiting": dict(self.waiting),
            }

    def results(self) -> dict[str, object]:
        with self.lock:
            if self.status != "done":
                raise AgentError(f"run is {self.status}, not done")
            start = self.start_mono_ns
            assert start is not None and self.end_mono_ns is not None
            events = [
                {**event, "offset_ns": int(event["mono_ns"]) - start} for event in self.events
            ]
            for event in events:
                event.pop("mono_ns", None)
            records = list(self.records)
            end_offset = self.end_mono_ns - start
            start_wall = self.start_wall_ns
        snapshots = {name: system.snapshot() for name, system in self.systems.items()}
        return {
            "schema": SCHEMA,
            "site": self.site,
            "run_id": self.config.run_id,
            "config": self.config.to_dict(),
            "start_wall_ns": start_wall,
            "end_offset_ns": end_offset,
            "plan_size": len(self.plan),
            "site_demand": site_demand(self.plan, self.config.sites),
            "records": sorted(records, key=lambda item: (str(item["system"]), int(item["index"]))),
            "events": events,
            "snapshots": snapshots,
            "effects": self.effects.summary(),
            "messages": {name: system.messages.value for name, system in self.systems.items()},
        }

    def close(self) -> None:
        for system in self.systems.values():
            system.close()
        self.effects.close()


class AgentState:
    def __init__(
        self, site: str, token: str, state_root: Path, anchor: AnchorSettings | None = None
    ) -> None:
        try:
            self.site = site_alias(site, "site")
        except ValueError as exc:
            raise AgentError(str(exc)) from None
        self.token = token
        self.state_root = state_root
        self.anchor = anchor
        self.lock = threading.RLock()
        self.run: Run | None = None
        self.transport: PeerTransport | None = None
        self.peer_nonces: dict[tuple[str, str], int] = {}

    def configure(self, body: Mapping[str, Any]) -> dict[str, object]:
        config = RunConfig.from_dict(mapping(body.get("config"), "config"))
        if self.site not in config.sites:
            raise AgentError(f"this site ({self.site}) is not in the run's sites")
        others = set(config.sites) - {self.site}
        peers = parse_peer_urls(body.get("peers"))
        if set(peers) != others:
            raise AgentError("peers must name exactly the other sites of the run")
        keys = mapping(body.get("keys"), "keys")
        seed = base64.b64decode(string(keys.get("seed"), "seed"), validate=True)
        public_keys = public_key_table(keys.get("public_keys"), config.sites)
        raft = mapping(body.get("raft", {}), "raft")
        raft_self = raft.get("self")
        raft_peers = {
            string(alias, "raft peer"): string(address, "raft address")
            for alias, address in mapping(raft.get("peers", {}), "raft.peers").items()
        }
        safe_run_id = "".join(
            character for character in config.run_id if character.isalnum() or character in "-_."
        )
        if safe_run_id != config.run_id or config.run_id.startswith("."):
            raise AgentError("run_id must be a safe path component")
        needs_raft = any(SystemSpec.parse(name).kind == "raft-quorum" for name in config.systems)
        if needs_raft and (raft_self is None or set(raft_peers) != others):
            raise AgentError("raft-quorum requires raft addresses for every site")
        with self.lock:
            if self.run is not None:
                raise AgentError("a run is already configured; tear it down first")
            state_dir = self.state_root / config.run_id / f"{self.site}-{time.time_ns()}"
            state_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            self.transport = PeerTransport(self.site, self.token, peers, config.peer_timeout_s)
            self.run = Run(
                self.site,
                config,
                state_dir,
                self.transport,
                seed,
                public_keys,
                None if raft_self is None else string(raft_self, "raft.self"),
                raft_peers,
                self.anchor,
            )
            return {
                "configured": True,
                "run_id": config.run_id,
                "plan_size": len(self.run.plan),
                "local_requests": len(self.run.local_plan),
                "sites": list(config.sites),
                "site_demand": site_demand(self.run.plan, config.sites),
                "shares": config.shares,
            }

    def require_run(self) -> Run:
        with self.lock:
            if self.run is None:
                raise AgentError("no run is configured")
            return self.run

    def teardown(self) -> dict[str, object]:
        with self.lock:
            run = self.run
            self.run = None
            self.transport = None
        if run is None:
            return {"torn_down": False}
        run.close()
        return {"torn_down": True, "run_id": run.config.run_id}

    def probe(self, target: str) -> dict[str, object]:
        with self.lock:
            transport = self.transport
        if transport is None:
            raise AgentError("no run is configured")
        started = time.perf_counter_ns()
        try:
            response = transport.post(target, "/peer/ping", {"source": self.site})
        except PeerUnreachableError:
            return {"target": target, "reachable": False, "latency_ns": None}
        except PeerRejectedError as exc:
            return {"target": target, "reachable": False, "rejected": str(exc), "latency_ns": None}
        return {
            "target": target,
            "reachable": response.get("pong") is True,
            "latency_ns": time.perf_counter_ns() - started,
        }

    def verify_peer_auth(
        self,
        *,
        path: str,
        source_alias: str,
        timestamp: str,
        nonce: str,
        body_sha256: str,
        authorization: str,
        body: bytes,
    ) -> bool:
        if not self.known_peer(source_alias):
            return False
        if len(nonce) != 64 or len(body_sha256) != 64:
            return False
        try:
            timestamp_value = int(timestamp)
        except ValueError:
            return False
        now = int(time.time())
        if abs(now - timestamp_value) > PEER_CLOCK_SKEW_SECONDS:
            return False
        if not hmac.compare_digest(hashlib.sha256(body).hexdigest(), body_sha256):
            return False
        prefix = "LETS-HMAC "
        if not authorization.startswith(prefix):
            return False
        expected = peer_mac(self.token, path, timestamp, nonce, body_sha256, source_alias)
        if not hmac.compare_digest(authorization[len(prefix) :], expected):
            return False
        with self.lock:
            expired = [key for key, expires in self.peer_nonces.items() if expires < now]
            for key in expired:
                self.peer_nonces.pop(key, None)
            key = (source_alias, nonce)
            if key in self.peer_nonces or len(self.peer_nonces) >= PEER_NONCE_CACHE_LIMIT:
                return False
            self.peer_nonces[key] = max(now, timestamp_value) + PEER_CLOCK_SKEW_SECONDS
        return True

    def known_peer(self, alias: str) -> bool:
        if alias == self.site or not SITE_ALIAS.fullmatch(alias):
            return False
        with self.lock:
            run = self.run
        return run is None or alias in run.config.sites

    def peer_request(self, path: str, source: str, body: Mapping[str, Any]) -> dict[str, object]:
        if path == "/peer/ping":
            return {"pong": True, "site": self.site}
        run = self.require_run()
        parts = path.split("/")
        if len(parts) != 5 or parts[1] != "peer":
            raise AgentError("unknown peer path")
        _, _, family, name, action = parts
        system = run.systems.get(name)
        if family == "central" and action == "take" and isinstance(system, CentralCounterSystem):
            return system.serve_take(string(body.get("request_id"), "request_id"), source)
        if family == "lets" and isinstance(system, LetsSystem):
            if action == "request-transfer":
                return system.serve_request_transfer(
                    source, integer(body.get("amount"), "amount", minimum=1)
                )
            if action == "finalize":
                return system.serve_finalize(source, mapping(body.get("ack"), "ack"))
        raise AgentError("unknown peer path")


class AgentServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = LISTEN_BACKLOG
    state: AgentState


class Handler(BaseHTTPRequestHandler):
    server: AgentServer

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _authorized(self) -> bool:
        expected = f"Bearer {self.server.state.token}"
        return hmac.compare_digest(self.headers.get("Authorization", ""), expected)

    def _raw_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY_BYTES:
            raise AgentError("request body size is invalid")
        return self.rfile.read(length)

    def _send(self, status: HTTPStatus, payload: Mapping[str, object]) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status.value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if not self._authorized():
            self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
            return
        state = self.server.state
        try:
            if self.path == "/health":
                with state.lock:
                    run_id = None if state.run is None else state.run.config.run_id
                self._send(
                    HTTPStatus.OK,
                    {"schema": SCHEMA, "ready": True, "site": state.site, "run_id": run_id},
                )
            elif self.path == "/run/status":
                self._send(HTTPStatus.OK, state.require_run().progress())
            elif self.path == "/run/results":
                self._send(HTTPStatus.OK, state.require_run().results())
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
        except AgentError as exc:
            self._send(HTTPStatus.CONFLICT, {"error": str(exc)})

    def do_POST(self) -> None:
        state = self.server.state
        try:
            raw = self._raw_body()
            if self.path.startswith("/peer/"):
                source = self.headers.get("X-LETS-Peer-Alias", "")
                if not state.verify_peer_auth(
                    path=self.path,
                    source_alias=source,
                    timestamp=self.headers.get("X-LETS-Timestamp", ""),
                    nonce=self.headers.get("X-LETS-Nonce", ""),
                    body_sha256=self.headers.get("X-LETS-Body-SHA256", ""),
                    authorization=self.headers.get("Authorization", ""),
                    body=raw,
                ):
                    self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized_peer_mac"})
                    return
                body = mapping(json.loads(raw or b"{}"), "request")
                self._send(HTTPStatus.OK, state.peer_request(self.path, source, body))
                return
            if not self._authorized():
                self._send(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            body = mapping(json.loads(raw or b"{}"), "request")
            if self.path == "/run/configure":
                result = state.configure(body)
            elif self.path == "/run/start":
                state.require_run().start(
                    integer(body.get("start_at_epoch_ns"), "start_at_epoch_ns", minimum=1)
                )
                result = {"started": True}
            elif self.path == "/run/teardown":
                result = state.teardown()
            elif self.path == "/probe/peer":
                target = string(body.get("target"), "target")
                if target not in state.require_run().config.sites or target == state.site:
                    raise AgentError("target must be another site of the run")
                result = state.probe(target)
            elif self.path == "/control/shutdown":
                result = {"shutting_down": True}
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self._send(HTTPStatus.NOT_FOUND, {"error": "not_found"})
                return
            self._send(HTTPStatus.OK, result)
        except (AgentError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self._send(HTTPStatus.BAD_REQUEST, {"error": str(exc)[:200]})
        except Exception as exc:
            self._send(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": type(exc).__name__, "detail": str(exc)[:200]},
            )


def serve(
    site: str,
    bind: str,
    port: int,
    token: str,
    state_root: Path,
    anchor: AnchorSettings | None = None,
) -> AgentServer:
    state = AgentState(site, token, state_root, anchor)
    state.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    server = AgentServer((bind, port), Handler)
    server.state = state
    return server


def _site_argument(value: str) -> str:
    try:
        return site_alias(value, "--site")
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", required=True, type=_site_argument)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument(
        "--token-env",
        default="LETS_E1_TOKEN",
        help="environment variable holding the shared control/peer token",
    )
    parser.add_argument(
        "--anchor-root",
        type=Path,
        help="directory for the process-file rollback anchors of the lets-anchored systems",
    )
    parser.add_argument(
        "--anchor-helper",
        default="",
        help="command that runs lets.authority_helper, e.g. under a separate account",
    )
    parser.add_argument("--anchor-timeout", type=float, default=5.0)
    return parser.parse_args()


def anchor_settings(root: Path | None, helper: str, timeout_s: float) -> AnchorSettings | None:
    if root is None:
        if helper:
            raise SystemExit("--anchor-helper requires --anchor-root")
        return None
    return AnchorSettings(root, tuple(shlex.split(helper)), timeout_s)


def main() -> int:
    arguments = _arguments()
    token = os.environ.get(arguments.token_env, "")
    if len(token) < 16:
        raise SystemExit(f"{arguments.token_env} must hold a token of at least 16 characters")
    anchor = anchor_settings(
        arguments.anchor_root, arguments.anchor_helper, arguments.anchor_timeout
    )
    server = serve(
        arguments.site, arguments.bind, arguments.port, token, arguments.state_root, anchor
    )
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "site": arguments.site,
                "port": arguments.port,
                "anchor_root": None if anchor is None else str(anchor.root),
                "anchor_helper": None if anchor is None else list(anchor.helper),
            }
        ),
        flush=True,
    )
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        server.state.teardown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
