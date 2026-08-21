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

Pull-request CI measures both the runtime package and the executable Astral case-study harness,
then uses the locked, development-only `diff-cover` dependency to require at least 90% coverage
of executable lines changed from `origin/main`. Reproduce that gate from a full-history checkout:

```powershell
uv run pytest -m "not e2e" --cov=lets --cov=benchmarks.astraldeep --cov-report=xml:coverage.xml
uv run diff-cover coverage.xml --compare-branch origin/main --fail-under=90
```

`diff-cover` remains in the `dev` extra and is not installed in LETS runtime artifacts.

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
