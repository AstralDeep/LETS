# Development and dependency isolation

LETS never installs Python packages into the system interpreter. The supported workflow uses
[`uv`](https://docs.astral.sh/uv/) to create and lock a repository-local `.venv`.

## Bootstrap

```powershell
uv sync --all-extras --frozen
```

For the first dependency resolution after intentionally editing `pyproject.toml`, omit `--frozen`
once and review the resulting `uv.lock` diff. Normal development and CI must use the frozen lock.

## Run tools

```powershell
uv run pytest
uv run ruff check .
uv run mypy src/lets
uv run lets --help
```

`uv run` selects `.venv` without relying on shell activation. To activate it manually in
PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Do not run `pip install` against the system interpreter. Do not commit `.venv`, caches, runtime
databases, generated keys, or local secrets.

## Containers

Production and integration images install from `uv.lock` into an image-local virtual environment.
The host `.venv` is neither copied into nor mounted into an image. Multi-node tests use persistent
Docker volumes only for each warden's independent database and explicitly generated development
credentials.

## Supported Python versions

The package floor is Python 3.11 because that is the AstralDeep integration runtime. CI covers
Python 3.11 through 3.14. The local development environment currently uses Python 3.14.
