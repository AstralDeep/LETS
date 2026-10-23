"""Shared vocabulary for the E1 experiment: the ordered site roster and everything derived from it
(links, Zipf weights, shares, parametric topologies), the system catalogue including the
`lets-tree-d<depth>-f<fanout>` delegation, `lets-anchored`, and stale-restore variants, the run
configuration record exchanged between controller.py and site_agent.py, and JSON/HMAC helpers.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA = "lets.fair-baselines/v1"
DEFAULT_SITES: tuple[str, ...] = ("s1", "s2", "s3")
MIN_SITES = 3
SITE_ALIAS = re.compile(r"[A-Za-z0-9_]{1,32}")
TENANT = "fair-baselines"
ENVELOPE_ID = "fair-baselines-envelope"
CAPABILITY = "fair-baselines.act"
SYSTEM_KINDS = ("central", "static-quota", "raft-quorum", "lets")
LETS_TREE = re.compile(r"lets-tree-d([1-9][0-9]?)-f([1-9][0-9]?)")
LETS_RESTORE = re.compile(r"(lets|lets-anchored)-restore@([A-Za-z0-9_]{1,32})")
RESTORE_SNAPSHOT_AFTER_CUT_S = 1.0
MAX_TREE_DEPTH = 8
MAX_TREE_FANOUT = 8
PLACEMENTS = ("equal", "proportional", "explicit")
DEFAULT_ENVELOPE = 30
FLAP_PERIOD_S = 3.0


def site_alias(value: object, name: str) -> str:
    if not isinstance(value, str) or not SITE_ALIAS.fullmatch(value):
        raise ValueError(f"{name} must be a site alias of 1-32 letters, digits, or underscores")
    return value


def site_roster(value: object, name: str = "sites") -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError(f"{name} must be a list of site aliases")
    sites = tuple(site_alias(item, name) for item in value)
    if len(sites) < MIN_SITES:
        raise ValueError(f"{name} must list at least {MIN_SITES} sites")
    if len(set(sites)) != len(sites):
        raise ValueError(f"{name} repeats a site alias")
    return sites


def site_links(sites: Sequence[str]) -> tuple[frozenset[str], ...]:
    return tuple(frozenset(pair) for pair in itertools.combinations(sites, 2))


SITES = DEFAULT_SITES
LINKS = site_links(DEFAULT_SITES)


def default_systems(sites: Sequence[str] = DEFAULT_SITES) -> tuple[str, ...]:
    roster = site_roster(sites)
    return (
        f"central-noretry@{roster[1]}",
        *(f"central-retry@{site}" for site in roster),
        "static-quota",
        "raft-quorum",
        "lets",
    )


DEFAULT_SYSTEMS = default_systems(DEFAULT_SITES)


@dataclass(frozen=True, slots=True)
class SystemSpec:
    name: str
    kind: str
    retry: bool
    host: str | None = None
    depth: int = 0
    fanout: int = 0
    anchored: bool = False
    restore_site: str | None = None

    @property
    def delegates(self) -> bool:
        return self.depth > 0

    @property
    def expected_unsafe(self) -> bool:
        return self.restore_site is not None and not self.anchored

    @classmethod
    def parse(cls, name: str, sites: Sequence[str] | None = None) -> SystemSpec:
        if name == "static-quota":
            return cls(name, "static-quota", retry=True)
        if name == "raft-quorum":
            return cls(name, "raft-quorum", retry=True)
        if name == "lets":
            return cls(name, "lets", retry=True)
        if name == "lets-anchored":
            return cls(name, "lets", retry=True, anchored=True)
        restore = LETS_RESTORE.fullmatch(name)
        if restore and (sites is None or restore.group(2) in sites):
            return cls(
                name,
                "lets",
                retry=True,
                anchored=restore.group(1) == "lets-anchored",
                restore_site=restore.group(2),
            )
        tree = LETS_TREE.fullmatch(name)
        if tree:
            depth, fanout = int(tree.group(1)), int(tree.group(2))
            if depth > MAX_TREE_DEPTH or fanout > MAX_TREE_FANOUT:
                raise ValueError(
                    f"{name!r} exceeds the tree limits (depth {MAX_TREE_DEPTH}, "
                    f"fanout {MAX_TREE_FANOUT})"
                )
            return cls(name, "lets", retry=True, depth=depth, fanout=fanout)
        base, separator, host = name.partition("@")
        if (
            separator
            and base in {"central-noretry", "central-retry"}
            and SITE_ALIAS.fullmatch(host)
            and (sites is None or host in sites)
        ):
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


def _links_touching(site: str, links: Sequence[frozenset[str]]) -> frozenset[frozenset[str]]:
    return frozenset(link for link in links if site in link)


def _link(name: str, left: str, right: str, sites: Sequence[str]) -> frozenset[str]:
    if left == right or left not in sites or right not in sites:
        raise ValueError(f"unknown topology {name!r}")
    return frozenset({left, right})


def resolve_topology(name: str, sites: Sequence[str] = DEFAULT_SITES) -> Topology:
    roster = site_roster(sites)
    links = site_links(roster)
    if name == "full-isolation":
        return Topology(name, frozenset(links))
    if name == "halves":
        head = set(roster[: math.ceil(len(roster) / 2)])
        return Topology(name, frozenset(link for link in links if len(link & head) == 1))
    parts = name.split("-")
    if len(parts) == 2 and parts[0] in {"isolate", "split"} and parts[1] in roster:
        return Topology(name, _links_touching(parts[1], links))
    if len(parts) == 2 and parts[0] == "bridge" and len(roster) == 3 and parts[1] in roster:
        others = [site for site in roster if site != parts[1]]
        return Topology(name, frozenset({frozenset(others)}))
    if len(parts) == 3 and parts[0] == "cut":
        return Topology(name, frozenset({_link(name, parts[1], parts[2], roster)}))
    if len(parts) == 3 and parts[0] == "flapping":
        link = _link(name, parts[1], parts[2], roster)
        return Topology(name, frozenset({link}), flap_period_s=FLAP_PERIOD_S)
    raise ValueError(f"unknown topology {name!r}")


def is_flapping(name: str) -> bool:
    return name.startswith("flapping-")


LEGACY_TOPOLOGIES = ("split-s1", "bridge-s3", "full-isolation", "flapping-s1-s2")


def default_topologies(sites: Sequence[str] = DEFAULT_SITES) -> tuple[str, ...]:
    roster = site_roster(sites)
    if roster == DEFAULT_SITES:
        return LEGACY_TOPOLOGIES
    return (
        f"isolate-{roster[0]}",
        "halves",
        "full-isolation",
        f"flapping-{roster[0]}-{roster[1]}",
    )


def topology_catalogue(sites: Sequence[str] = DEFAULT_SITES) -> dict[str, Topology]:
    roster = site_roster(sites)
    names = [
        *default_topologies(roster),
        *(f"isolate-{site}" for site in roster),
        "halves",
        "full-isolation",
        f"cut-{roster[0]}-{roster[1]}",
        f"flapping-{roster[0]}-{roster[1]}",
    ]
    return {name: resolve_topology(name, roster) for name in dict.fromkeys(names)}


TOPOLOGIES: dict[str, Topology] = topology_catalogue(DEFAULT_SITES)
STATIC_TOPOLOGIES = tuple(name for name in LEGACY_TOPOLOGIES if not is_flapping(name))
TOPOLOGY_ORDER = ("split-", "isolate-", "cut-", "bridge-", "halves", "full-isolation", "flapping-")


def topology_order(names: Sequence[str]) -> list[str]:
    def rank(name: str) -> tuple[int, str]:
        for index, prefix in enumerate(TOPOLOGY_ORDER):
            if name == prefix or name.startswith(prefix):
                return index, name
        return len(TOPOLOGY_ORDER), name

    return sorted(dict.fromkeys(names), key=rank)


def zipf_weights(theta: float, count: int = len(DEFAULT_SITES)) -> tuple[float, ...]:
    if theta < 0 or count < 1:
        raise ValueError("theta must be non-negative and count positive")
    raw = [1.0 / float(rank) ** theta for rank in range(1, count + 1)]
    total = sum(raw)
    return tuple(value / total for value in raw)


def validate_shares(
    value: object, sites: Sequence[str], envelope: int, name: str = "shares"
) -> dict[str, int]:
    table = mapping(value, name)
    roster = site_roster(sites)
    if set(table) != set(roster):
        raise ValueError(f"{name} must name exactly the sites {list(roster)}")
    shares = {site: integer(table[site], f"{name}[{site!r}]", minimum=1) for site in roster}
    if sum(shares.values()) != envelope:
        raise ValueError(f"{name} must sum to the envelope ({envelope})")
    return shares


def share_placement(
    placement: str,
    envelope: int,
    theta: float,
    sites: Sequence[str] = DEFAULT_SITES,
    explicit: Mapping[str, int] | None = None,
) -> dict[str, int]:
    roster = site_roster(sites)
    if envelope < len(roster):
        raise ValueError("envelope must hold at least one unit per site")
    if placement == "explicit":
        if explicit is None:
            raise ValueError("explicit placement needs a shares mapping")
        return validate_shares(explicit, roster, envelope)
    if placement == "equal":
        weights = zipf_weights(0.0, len(roster))
    elif placement == "proportional":
        weights = zipf_weights(theta, len(roster))
    else:
        raise ValueError(f"unknown placement {placement!r}")
    shares = [max(1, math.floor(weight * envelope)) for weight in weights]
    remainder = envelope - sum(shares)
    order = sorted(range(len(roster)), key=lambda index: -weights[index])
    for step in range(abs(remainder)):
        index = order[step % len(order)]
        shares[index] += 1 if remainder > 0 else -1
    return dict(zip(roster, shares, strict=True))


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
    sites: tuple[str, ...] = DEFAULT_SITES
    explicit_shares: dict[str, int] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def arrival_window_s(self) -> float:
        return self.pre_s + self.partition_s + self.post_s

    @property
    def restore_schedule_s(self) -> tuple[float, float]:
        snapshot = self.pre_s + min(RESTORE_SNAPSHOT_AFTER_CUT_S, self.partition_s / 4)
        return snapshot, self.pre_s + self.partition_s / 2

    @property
    def shares(self) -> dict[str, int]:
        return share_placement(
            self.placement, self.envelope, self.theta, self.sites, self.explicit_shares
        )

    def resolved_topology(self) -> Topology:
        return resolve_topology(self.topology, self.sites)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["systems"] = list(self.systems)
        payload["sites"] = list(self.sites)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RunConfig:
        data = dict(payload)
        sites = site_roster(data.pop("sites", DEFAULT_SITES))
        systems = tuple(str(item) for item in data.pop("systems"))
        for name in systems:
            SystemSpec.parse(name, sites)
        resolve_topology(str(data["topology"]), sites)
        extra = dict(data.pop("extra", {}))
        explicit = data.pop("explicit_shares", None)
        envelope = data.get("envelope")
        if isinstance(envelope, bool) or not isinstance(envelope, int) or envelope < 1:
            raise ValueError("envelope, load, and theta must be positive")
        placement = str(data.get("placement"))
        if placement not in PLACEMENTS:
            raise ValueError(f"unknown placement {placement!r}")
        if explicit is not None:
            if placement != "explicit":
                raise ValueError("explicit_shares requires the explicit placement")
            explicit = validate_shares(explicit, sites, envelope, "explicit_shares")
        config = cls(sites=sites, systems=systems, extra=extra, explicit_shares=explicit, **data)
        if config.load <= 0 or config.theta < 0:
            raise ValueError("envelope, load, and theta must be positive")
        if min(config.pre_s, config.partition_s, config.post_s, config.deadline_s) < 0:
            raise ValueError("phase durations must be non-negative")
        if config.arrival_window_s <= 0:
            raise ValueError("the arrival window must be positive")
        share_placement(placement, envelope, config.theta, sites, explicit)
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


def site_list(value: object, name: str, sites: Sequence[str] = DEFAULT_SITES) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError(f"{name} must be a list of site aliases")
    listed = tuple(string(item, name) for item in value)
    unknown = set(listed) - set(sites)
    if unknown:
        raise ValueError(f"{name} names unknown sites {sorted(unknown)}")
    return listed
