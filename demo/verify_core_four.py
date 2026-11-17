"""Headless check that the four demo claims actually hold against a live warden.

Run with the warden serving on loopback. Exits non-zero on any failure so it can
double as a smoke test for the dashboard.
"""

from __future__ import annotations

import sys
from pathlib import Path

from demo.config import Settings
from demo.fleet import Fleet

failures: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail}" if detail else ""))
    if not condition:
        failures.append(name)


def vec(state, subject):
    for lease in state["leases"]:
        if lease["subject_id"] == subject:
            return lease
    return None


# Its own registry file, so running this against a live demo server does not
# adopt (and then close) the leases that server is showing in the browser. The
# path is profile-scoped because lease IDs are node-local -- the dev and
# production wardens must never share a registry.
settings = Settings.load()
print(f"== warden: {settings.base_url}  (profile: {settings.profile}) ==")
fleet = Fleet(settings, registry_path=settings.registry_path("verify"))
fleet.start()
fleet.reset()

print("\n== claim 3: ledger balances from the start ==")
state = fleet.snapshot()
check("ledger balanced at rest", state["ledger"]["balanced"], str(state["ledger"]["rows"][0]))
genesis = state["ledger"]["initial_share"]
# Budget already consumed on this node stays consumed, so the free pool does not
# necessarily start at the genesis share. Measure deltas, not absolutes, so this
# script is valid against a node with history.
pool_before = state["ledger"]["free_pool"]
residual_before = state["ledger"]["lease_residual"]

print("\n== provision root ==")
event = fleet.provision_root()
check("root issued", event.ok, event.detail or event.note or "")
state = fleet.snapshot()
root = vec(state, "agent-root")
check("root residual == allocation", root["residual"] == root["allocation"], str(root["residual"]))
check("ledger still balanced", state["ledger"]["balanced"])
check("free pool fell by exactly the allocation",
      [b - a for b, a in zip(pool_before, state["ledger"]["free_pool"])] == root["allocation"],
      f"{pool_before} -> {state['ledger']['free_pool']}, allocation {root['allocation']}")
root_id = root["lease_id"]

print("\n== claim 1a: a child is escrowed out of its parent ==")
before = vec(fleet.snapshot(), "agent-root")["residual"]
event = fleet.spawn_child(root_id)
check("child spawned", event.ok, event.detail or event.note or "")
state = fleet.snapshot()
after = vec(state, "agent-root")["residual"]
child = [l for l in state["leases"] if l["depth"] == 1][0]
check("parent residual fell by exactly the child allocation",
      [b - a for b, a in zip(before, after)] == child["allocation"],
      f"{before} -> {after}, child got {child['allocation']}")
check("ledger still balanced", state["ledger"]["balanced"])

print("\n== claim 1b: a child cannot outspend its parent ==")
tree_before = [dict(l) for l in fleet.snapshot()["leases"]]
event = fleet.spawn_oversized(root_id)
check("oversized spawn DENIED", not event.ok, f"{event.code}: {event.detail}")
check("denial code is policy_denied", event.code == "policy_denied", str(event.code))
state = fleet.snapshot()
check("denial moved nothing in the ledger", event.ledger_unchanged is True)
check("tree identical before and after denial", tree_before == [dict(l) for l in state["leases"]])
check("ledger still balanced", state["ledger"]["balanced"])

print("\n== claim 2: capability attenuation is one-way ==")
event = fleet.spawn_escalated(root_id)
check("escalated spawn DENIED", not event.ok, f"{event.code}: {event.detail}")
check("denied for capabilities, not for an undeclared name",
      "undeclared" not in (event.detail or "").lower(),
      event.detail or "")
state = fleet.snapshot()
check("ledger still balanced", state["ledger"]["balanced"])

print("\n== claim 4: work debits the residual ==")
before_lease = vec(fleet.snapshot(), "agent-root")
before_consumed = fleet.snapshot()["ledger"]["consumed"]
event = fleet.do_work(root_id, "research")
check("work authorized", event.ok, event.detail or event.note or "")
state = fleet.snapshot()
after_lease = vec(state, "agent-root")
cost = [1, 500]
check("residual fell by exactly the transition cost",
      [b - a for b, a in zip(before_lease["residual"], after_lease["residual"])] == cost,
      f"{before_lease['residual']} -> {after_lease['residual']}")
check("consumed rose by exactly the transition cost",
      [a - b for a, b in zip(state["ledger"]["consumed"], before_consumed)] == cost)
check("sequence advanced", after_lease["sequence"] > before_lease["sequence"],
      f"{before_lease['sequence']} -> {after_lease['sequence']}")
check("ledger still balanced", state["ledger"]["balanced"])

print("\n== claim 4b: a drained agent stops being able to act ==")
events = fleet.drain(child["lease_id"], "research")
allowed = sum(1 for e in events if e.ok)
final = events[-1]
check("drain ended in a denial", not final.ok, f"{final.code}: {final.detail}")
check("some work succeeded first", allowed > 0, f"{allowed} allowed")
state = fleet.snapshot()
check("ledger still balanced after drain", state["ledger"]["balanced"])

print("\n== reset ==")
event = fleet.reset()
check("reset ok", event.ok, event.detail or "")
state = fleet.snapshot()
check("tree empty", state["leases"] == [])
check("ledger still balanced", state["ledger"]["balanced"])
check("every lease this script opened was closed",
      state["ledger"]["lease_residual"] == residual_before,
      f"residual {residual_before} at start -> {state['ledger']['lease_residual']} now")
print(f"  free pool after reset: {state['ledger']['free_pool']} (genesis {genesis})")
print(f"  consumed after reset:  {state['ledger']['consumed']}")

fleet.close()

print("\n" + "=" * 60)
if failures:
    print(f"FAILED ({len(failures)}): " + ", ".join(failures))
    sys.exit(1)
print("ALL CHECKS PASSED")
