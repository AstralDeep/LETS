"""Measure invariant-snapshot latency as the durable lease table grows."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from benchmarks.run import _environment
from lets.clock import ManualClock
from lets.crypto import Ed25519Signer, PublicKeyRegistry
from lets.models import IdentityContext
from lets.service import WardenService
from lets.storage import SQLiteStorage

POLICY_DIGEST = "sha256:" + "1" * 64
MACHINE_DIGEST = "sha256:" + "2" * 64


def _summary(samples: list[int]) -> dict[str, int]:
    ordered = sorted(samples)
    return {
        "minimum": ordered[0],
        "median": int(statistics.median(ordered)),
        "mean": int(statistics.fmean(ordered)),
        "p95": ordered[max(0, (len(ordered) * 95 + 99) // 100 - 1)],
        "maximum": ordered[-1],
    }


def profile_invariants(
    workspace: Path,
    *,
    counts: tuple[int, ...],
    samples: int,
) -> dict[str, Any]:
    if not counts or tuple(sorted(set(counts))) != counts or any(count <= 0 for count in counts):
        raise ValueError("counts must be unique positive integers in ascending order")
    if samples <= 0:
        raise ValueError("samples must be positive")
    workspace.mkdir(parents=True, exist_ok=True)
    observations = []
    with TemporaryDirectory(prefix="lets-invariants-", dir=workspace) as temporary:
        directory = Path(temporary)
        for count in counts:
            signer = Ed25519Signer.generate(f"warden-invariants-{count}")
            store = SQLiteStorage.initialize(
                directory / f"invariants-{count}.sqlite3",
                signer.warden_id,
                (count,),
                signing_key_id=signer.key_id,
                signing_public_key=signer.public_key_bytes,
                tenant_id="benchmark",
                envelope_id="benchmark-envelope",
                initial_local_share=(count,),
            )
            try:
                with store.write() as transaction:
                    transaction.insert_policy(
                        policy_version="v1",
                        policy_digest=POLICY_DIGEST,
                        machine_digest=MACHINE_DIGEST,
                        payload={"policy_id": "invariant-profile"},
                        active=True,
                        created_at_ns=1,
                    )
                    for index in range(count):
                        transaction.insert_lease(
                            {
                                "lease_id": f"lease-{index}",
                                "lineage_id": f"lineage-{index}",
                                "subject_id": "agent",
                                "allocation": (1,),
                                "residual": (1,),
                                "capabilities": ("step",),
                                "machine_digest": MACHINE_DIGEST,
                                "ancestor_path": (),
                                "issued_at_ns": 2,
                                "expires_at_ns": 100_000,
                                "key_id": signer.key_id,
                                "signature": b"signature",
                                "state": "ready",
                                "status": "ACTIVE",
                                "policy_version": "v1",
                                "policy_digest": POLICY_DIGEST,
                            }
                        )
                    transaction.update_warden_state(free_pool=(0,), updated_at_ns=2)
                registry = PublicKeyRegistry()
                registry.register_signer(signer)
                service = WardenService(
                    store,
                    signer=signer,
                    clock=ManualClock(100),
                    trust_registry=registry,
                )
                identity = IdentityContext("auditor", "benchmark", frozenset())
                latencies = []
                for _ in range(samples):
                    start = time.perf_counter_ns()
                    snapshot = service.invariant_snapshot(identity=identity)
                    latencies.append(time.perf_counter_ns() - start)
                    if not snapshot.healthy or snapshot.lease_residual != (count,):
                        raise RuntimeError("invariant profile observed an unhealthy ledger")
                observations.append(
                    {
                        "lease_rows": count,
                        "samples": samples,
                        "latency_ns": _summary(latencies),
                    }
                )
            finally:
                store.close()
    return {
        "schema": "lets.invariant-scaling-profile/v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": _environment(Path(__file__).resolve().parents[1]),
        "implementation": (
            "trigger-maintained lease_residual aggregate; startup/diagnostic full reconciliation"
        ),
        "observations": observations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--counts", type=int, nargs="+", default=(10, 100, 1_000))
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/invariants.json"),
    )
    arguments = parser.parse_args()
    result = profile_invariants(
        Path("benchmarks/results"),
        counts=tuple(arguments.counts),
        samples=arguments.samples,
    )
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps({"output": str(arguments.output)}, sort_keys=True))


if __name__ == "__main__":
    main()
