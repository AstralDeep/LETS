"""Internal atomic file-anchor helper used by the production runtime provider."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

from lets.authority import AuthorityCheckpoint, FileAuthorityAnchor
from lets.canonical import canonical_json, strict_json_loads
from lets.errors import StorageError, ValidationError

if TYPE_CHECKING:
    from lets.executor_authority import ExecutorAuthorityCheckpoint


def _checkpoint(value: object, field: str) -> AuthorityCheckpoint:
    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be an authority checkpoint")
    return AuthorityCheckpoint.from_dict(value)


def _executor_checkpoint(value: object, field: str) -> ExecutorAuthorityCheckpoint:
    from lets.executor_authority import ExecutorAuthorityCheckpoint

    if not isinstance(value, Mapping):
        raise ValidationError(f"{field} must be an executor authority checkpoint")
    return ExecutorAuthorityCheckpoint.from_dict(value)


def _respond(value: Mapping[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json(dict(value)) + b"\n")
    sys.stdout.buffer.flush()


def _operate(path: Path, request: Mapping[str, Any]) -> Mapping[str, object]:
    operation = request.get("operation")
    anchor = FileAuthorityAnchor(path, timeout_s=60.0)
    with anchor._locked():
        exists = anchor.path.exists()
        if operation == "read":
            if set(request) != {"operation"}:
                raise ValidationError("read request fields are invalid")
            if not exists:
                return {"status": "missing"}
            return {"status": "ok", "checkpoint": anchor._read().to_dict()}
        if operation == "initialize":
            if set(request) != {"operation", "checkpoint"}:
                raise ValidationError("initialize request fields are invalid")
            if exists:
                return {"status": "conflict"}
            checkpoint = _checkpoint(request.get("checkpoint"), "checkpoint")
            anchor._write(checkpoint, exclusive=True)
            return {"status": "ok"}
        if operation == "compare-and-set":
            if set(request) != {"operation", "expected", "checkpoint"}:
                raise ValidationError("compare-and-set request fields are invalid")
            if not exists:
                return {"status": "conflict"}
            expected = _checkpoint(request.get("expected"), "expected")
            checkpoint = _checkpoint(request.get("checkpoint"), "checkpoint")
            if anchor._read() != expected:
                return {"status": "conflict"}
            anchor._write(checkpoint, exclusive=False)
            return {"status": "ok"}
    raise ValidationError("unsupported authority anchor operation")


def _operate_executor(path: Path, request: Mapping[str, Any]) -> Mapping[str, object]:
    from lets.executor_authority import FileExecutorAuthorityAnchor

    operation = request.get("operation")
    anchor = FileExecutorAuthorityAnchor(path, timeout_s=60.0)
    with anchor._locked():
        exists = anchor.path.exists()
        if operation == "read":
            if set(request) != {"operation"}:
                raise ValidationError("read request fields are invalid")
            if not exists:
                return {"status": "missing"}
            return {"status": "ok", "checkpoint": anchor._read_executor().to_dict()}
        if operation == "initialize":
            if set(request) != {"operation", "checkpoint"}:
                raise ValidationError("initialize request fields are invalid")
            if exists:
                return {"status": "conflict"}
            checkpoint = _executor_checkpoint(request.get("checkpoint"), "checkpoint")
            anchor._write_executor(checkpoint, exclusive=True)
            return {"status": "ok"}
        if operation == "compare-and-set":
            if set(request) != {"operation", "expected", "checkpoint"}:
                raise ValidationError("compare-and-set request fields are invalid")
            if not exists:
                return {"status": "conflict"}
            expected = _executor_checkpoint(request.get("expected"), "expected")
            checkpoint = _executor_checkpoint(request.get("checkpoint"), "checkpoint")
            if anchor._read_executor() != expected:
                return {"status": "conflict"}
            anchor._write_executor(checkpoint, exclusive=False)
            return {"status": "ok"}
    raise ValidationError("unsupported executor authority anchor operation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--format", choices=("warden", "executor"), default="warden")
    parser.add_argument("--path", required=True)
    namespace = parser.parse_args(argv)
    while request := sys.stdin.buffer.readline(1024 * 1024 + 1):
        try:
            if len(request) > 1024 * 1024 or not request.endswith(b"\n"):
                raise ValidationError("authority helper request is oversized or unterminated")
            decoded = strict_json_loads(request)
            if not isinstance(decoded, Mapping):
                raise ValidationError("authority helper request must be an object")
            operation = _operate if namespace.format == "warden" else _operate_executor
            response = operation(Path(namespace.path).resolve(), decoded)
            _respond(response)
        except (StorageError, ValidationError, OSError, UnicodeError, ValueError) as exc:
            _respond({"status": "error", "error": str(exc)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
