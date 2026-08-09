from pathlib import Path


def test_docker_context_excludes_runtime_secrets_and_authority_state() -> None:
    repository = Path(__file__).parents[2]
    rules = {
        line.strip()
        for line in (repository / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required = {
        ".git",
        ".venv",
        "*.db",
        "*.db-shm",
        "*.db-wal",
        "*.sqlite",
        "*.sqlite-shm",
        "*.sqlite-wal",
        "*.sqlite3",
        "*.sqlite3-shm",
        "*.sqlite3-wal",
        "*.pem",
        "*.key",
        "*.ed25519",
        "*.seed",
        "*.token",
        "*.p12",
        "*.pfx",
        ".env",
        ".env.*",
        ".lets",
        "data",
        "state",
        "run",
        "logs",
        "*.log",
    }

    assert required <= rules
