"""Shared vocabulary for the E1 experiment: site aliases, system and topology catalogues, the run
configuration record exchanged between controller.py and site_agent.py, and the small JSON/HMAC
helpers both ends use.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA = "lets.fair-baselines/v1"
SITES: tuple[str, str, str] = ("s1", "s2", "s3")
LINKS: tuple[frozenset[str], ...] = (
    frozenset({"s1", "s2"}),
    frozenset({"s1", "s3"}),
    frozenset({"s2", "s3"}),
)
TENANT = "fair-baselines"
ENVELOPE_ID = "fair-baselines-envelope"
CAPABILITY = "fair-baselines.act"
SYSTEM_KINDS = ("central", "static-quota", "raft-quorum", "lets")
DEFAULT_SYSTEMS = (
    "central-noretry@s2",
    "central-retry@s1",
    "central-retry@s2",
    "central-retry@s3",
    "static-quota",
    "raft-quorum",
    "lets",
)
DEFAULT_ENVELOPE = 30


@dataclass(frozen=True, slots=True)
class SystemSpec:
    name: str
    kind: str
    retry: bool
    host: str | None = None

    @classmethod
    def parse(cls, name: str) -> SystemSpec:
        if name == "static-quota":
            return cls(name, "static-quota", retry=True)
        if name == "raft-quorum":
            return cls(name, "raft-quorum", retry=True)
        if name == "lets":
            return cls(name, "lets", retry=True)
        base, separator, host = name.partition("@")
        if separator and host in SITES and base in {"central-noretry", "central-retry"}:
            return cls(name, "central", retry=base == "central-retry", host=host)
        raise ValueError(f"unknown system {name!r}")


@dataclass(frozen=True, slots=True)
class Topology:
    name: str
    cut_links: frozenset[frozenset[str]]
    flap_period_s: float | None = None

    def link_is_cut(self, link: frozenset[str], offset_s: float, partition_start_s: float) -> bool:
        if link not in self.cut_links:
            return False
        if self.flap_period_s is None:
            return True
        cycles = math.floor((offset_s - partition_start_s) / self.flap_period_s)
        return cycles % 2 == 0


TOPOLOGIES: dict[str, Topology] = {
    "split-s1": Topology("split-s1", frozenset({LINKS[0], LINKS[1]})),
    "bridge-s3": Topology("bridge-s3", frozenset({LINKS[0]})),
    "full-isolation": Topology("full-isolation", frozenset(LINKS)),
    "flapping-s1-s2": Topology("flapping-s1-s2", frozenset({LINKS[0]}), flap_period_s=3.0),
}
STATIC_TOPOLOGIES = ("split-s1", "bridge-s3", "full-isolation")


def zipf_weights(theta: float, count: int = len(SITES)) -> tuple[float, ...]:
    if theta < 0 or count < 1:
        raise ValueError("theta must be non-negative and count positive")
    raw = [1.0 / float(rank) ** theta for rank in range(1, count + 1)]
    total = sum(raw)
    return tuple(value / total for value in raw)


def share_placement(placement: str, envelope: int, theta: float) -> dict[str, int]:
    if envelope < len(SITES):
        raise ValueError("envelope must hold at least one unit per site")
    if placement == "equal":
        weights = zipf_weights(0.0)
    elif placement == "proportional":
        weights = zipf_weights(theta)
    else:
        raise ValueError(f"unknown placement {placement!r}")
    shares = [max(1, math.floor(weight * envelope)) for weight in weights]
    remainder = envelope - sum(shares)
    order = sorted(range(len(SITES)), key=lambda index: -weights[index])
    for step in range(abs(remainder)):
        index = order[step % len(order)]
        shares[index] += 1 if remainder > 0 else -1
    return dict(zip(SITES, shares, strict=True))


@dataclass(frozen=True, slots=True)
class RunConfig:
    run_id: str
    topology: str
    load: float
    theta: float
    seed: int
    placement: str
    envelope: int
    systems: tuple[str, ...]
    pre_s: float
    partition_s: float
    post_s: float
    deadline_s: float
    retry_base_s: float = 0.2
    retry_cap_s: float = 1.0
    peer_timeout_s: float = 2.0
    raft_timeout_s: float = 2.0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def arrival_window_s(self) -> float:
        return self.pre_s + self.partition_s + self.post_s

    @property
    def shares(self) -> dict[str, int]:
        return share_placement(self.placement, self.envelope, self.theta)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["systems"] = list(self.systems)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RunConfig:
        data = dict(payload)
        systems = tuple(str(item) for item in data.pop("systems"))
        for name in systems:
            SystemSpec.parse(name)
        if data["topology"] not in TOPOLOGIES:
            raise ValueError(f"unknown topology {data['topology']!r}")
        extra = dict(data.pop("extra", {}))
        config = cls(systems=systems, extra=extra, **data)
        if config.envelope < 1 or config.load <= 0 or config.theta < 0:
            raise ValueError("envelope, load, and theta must be positive")
        if min(config.pre_s, config.partition_s, config.post_s, config.deadline_s) < 0:
            raise ValueError("phase durations must be non-negative")
        if config.arrival_window_s <= 0:
            raise ValueError("the arrival window must be positive")
        return config


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def peer_mac(
    token: str, path: str, timestamp: str, nonce: str, body_sha256: str, alias: str
) -> str:
    canonical = "\n".join(("POST", path, timestamp, nonce, body_sha256, alias)).encode("utf-8")
    return hmac.new(token.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def mapping(value: object, name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return dict(value)


def integer(value: object, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def string(value: object, name: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{name} must be a non-empty string")
    return value


def site_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError(f"{name} must be a list of site aliases")
    sites = tuple(string(item, name) for item in value)
    unknown = set(sites) - set(SITES)
    if unknown:
        raise ValueError(f"{name} names unknown sites {sorted(unknown)}")
    return sites
