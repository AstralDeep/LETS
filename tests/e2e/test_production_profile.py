"""Opt-in execution gate for the hardened production-profile topology."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        os.environ.get("LETS_RUN_PRODUCTION_ACCEPTANCE") != "1",
        reason="set LETS_RUN_PRODUCTION_ACCEPTANCE=1 to run the mTLS production profile",
    ),
]

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "results" / "generated" / "production-profile-acceptance.json"


def test_production_profile_acceptance() -> None:
    result = subprocess.run(
        [sys.executable, "deploy/production/run_acceptance.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=1_200,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    assert evidence["schema"] == "lets.production-profile-acceptance/v1"
    assert evidence["scenario"]["status"] == "passed"
    assert evidence["executor"]["status"] == "passed"
    assert evidence["executor"]["anchored_replay_store"] is True
    assert evidence["executor"]["duplicate_receipt_rejected_after_reopen"] is True
    assert evidence["executor"]["stale_database_restore_rejected"] is True
    assert evidence["executor"]["independent_state_and_anchor_domains"] is True
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", evidence["source"]["tree_digest"])
    assert evidence["restart"]["process_replaced"] is True
    assert evidence["security"]["missing_client_certificate_rejected"] is True
    assert evidence["security"]["untrusted_client_certificate_rejected"] is True
    assert evidence["security"]["expired_jwt_rejected"] is True
    assert evidence["security"]["sqlite_wal_reset_fix"] is True
    assert all(
        re.fullmatch(r"[0-9]+(?:\.[0-9]+){2,}", warden["sqlite_version"])
        for warden in evidence["security"]["wardens"].values()
    )
    assert all(
        node["audit_archive"]["bytes"] > 0
        and node["audit_archive"]["records"] > 0
        and node["audit_archive"]["head_sequence"] >= 0
        for node in evidence["hardening"].values()
    )
