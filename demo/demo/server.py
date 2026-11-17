"""HTTP front end for the demo.

Sits between the browser and the warden so the bootstrap token never leaves this
process. Every action endpoint returns the full post-action state, so the
dashboard stays a pure function of one payload and cannot drift out of sync with
the runtime.

Handlers are sync `def` on purpose: `LETSClient` is blocking, so FastAPI runs
them in its threadpool rather than stalling the event loop.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from demo.config import Settings
from demo.fleet import Fleet

STATIC = Path(__file__).resolve().parent / "static"

_fleet: Fleet | None = None


def fleet() -> Fleet:
    if _fleet is None:  # pragma: no cover - startup ordering guard
        raise RuntimeError("fleet is not initialized")
    return _fleet


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _fleet
    _fleet = Fleet(Settings.load())
    _fleet.start()
    print(f"[demo] policy registered: {_fleet.policy_digest}")
    yield
    _fleet.close()


app = FastAPI(title="LETS Demo", lifespan=lifespan, docs_url=None, redoc_url=None)


class LeaseBody(BaseModel):
    lease_id: str


class WorkBody(BaseModel):
    lease_id: str
    transition: str = "research"


app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/docs")
def docs() -> FileResponse:
    """How LETS works — the concepts behind what the register is showing."""
    return FileResponse(STATIC / "docs.html")


@app.get("/delegation")
def delegation() -> FileResponse:
    """A step-through of what delegation does to an agent's budget."""
    return FileResponse(STATIC / "delegation.html")


@app.get("/api/state")
def state() -> dict[str, Any]:
    return fleet().snapshot()


@app.post("/api/provision-root")
def provision_root() -> dict[str, Any]:
    fleet().provision_root()
    return fleet().snapshot()


@app.post("/api/spawn-child")
def spawn_child(body: LeaseBody) -> dict[str, Any]:
    fleet().spawn_child(body.lease_id)
    return fleet().snapshot()


@app.post("/api/spawn-oversized")
def spawn_oversized(body: LeaseBody) -> dict[str, Any]:
    fleet().spawn_oversized(body.lease_id)
    return fleet().snapshot()


@app.post("/api/spawn-escalated")
def spawn_escalated(body: LeaseBody) -> dict[str, Any]:
    fleet().spawn_escalated(body.lease_id)
    return fleet().snapshot()


@app.post("/api/work")
def work(body: WorkBody) -> dict[str, Any]:
    fleet().do_work(body.lease_id, body.transition)
    return fleet().snapshot()


@app.post("/api/drain")
def drain(body: WorkBody) -> dict[str, Any]:
    fleet().drain(body.lease_id, body.transition)
    return fleet().snapshot()


@app.post("/api/reset")
def reset() -> dict[str, Any]:
    fleet().reset()
    return fleet().snapshot()


@app.get("/api/audit")
def audit(tail: int = 50) -> JSONResponse:
    """The warden's own hash-chained log, for cross-checking the dashboard.

    `/v1/audit` pages forward from a sequence cursor, and the log is cumulative
    for the life of the node — so reading from the start returns the oldest
    records, not the ones that just happened. Page to the end and keep the tail.
    """
    client = fleet()._client
    records: list[dict] = []
    cursor = -1
    while True:
        page = client.audit(after_sequence=cursor, limit=1000).get("records", [])
        if not page:
            break
        records.extend(page)
        cursor = page[-1]["sequence"]
        if len(page) < 1000:
            break
    return JSONResponse(
        {
            "verify": client.verify_audit(),
            "total": len(records),
            "records": records[-tail:],
        }
    )
