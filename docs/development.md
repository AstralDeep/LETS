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

CI measures both the runtime package and the executable Astral case-study harness, then uses the
standalone, hash-locked CI tooling environment to require at least 90% coverage of executable
lines changed since a base commit: the pull request's base, or for a push to `main` the commit the
push replaced. The step fails closed when that base is missing, is not a 40-hex SHA, is the
all-zero SHA, or is absent from the full-history checkout. Reproduce it against the merge base
with `origin/main`:

```powershell
uv run pytest -m "not e2e" --cov=lets --cov=benchmarks.astraldeep --cov-report=xml:coverage.xml
uv venv --python 3.14 .ci-tools
uv pip install --python .ci-tools --require-hashes -r tooling/python-ci/requirements.lock.txt
$base = git merge-base origin/main HEAD
& .\.ci-tools\Scripts\diff-cover.exe coverage.xml --compare-branch $base `
  --diff-range-notation '..' --fail-under=90 --format json:changed-coverage-report.json
& .\.ci-tools\Scripts\python.exe scripts\check_changed_coverage.py `
  --report changed-coverage-report.json --base-sha $base --fail-under 90 `
  --output changed-coverage-decision.json
```

`scripts/check_changed_coverage.py` prints and writes the decision, naming the base and candidate
commits and every changed path. It records `pass` or `fail` against the threshold whenever the
diff has measurable lines, and an explicit `not-applicable` decision when the diff has no
executable lines in the measured packages. CI runs it even when `diff-cover` fails, so a failing
decision is recorded too, and still fails the step. The recorder rejects a report produced for a
different comparison or whose totals are inconsistent.

`diff-cover` and its transitive dependencies are exact-pinned with artifact hashes in
`tooling/python-ci/requirements.lock.txt`. They are absent from LETS package metadata,
`uv.lock`, and runtime artifacts.

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
