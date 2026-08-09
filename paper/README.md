# Rebuilding the LETS paper

`paper.tex` is the maintained system paper for the implemented LETS runtime.
`original-draft.pdf` is historical source material and is never overwritten.

The build is isolated in a digest-pinned TeX Live container; it installs nothing into the host
Python or operating system. From the repository root:

```powershell
make paper
make paper-check
make paper-render
```

The targets produce:

- `paper/lets.pdf`: final, tracked manuscript;
- `paper/build/`: ignored LaTeX intermediates and rendered QA pages;
- `paper/build/render/page-*.png`: one PNG per final PDF page.

The first invocation may download the pinned TeX and Poppler images. To use pre-approved mirrors,
set `PAPER_IMAGE` and `PAPER_RENDER_IMAGE` to equivalent image digests. The TeX image must contain
`latexmk` and BibTeX; rendering and PDF metadata checks use the separate Poppler image.

## Evidence discipline

Runtime values shown in the paper are centralized in `evidence.tex`. Update those macros only
from reproduced commands and retained evidence. The paper distinguishes:

- implemented source behavior;
- measured runs with an environment record;
- executable and bounded checks;
- design arguments that are not mechanized proofs;
- future work.

The production-profile acceptance record is reproduced with the repository-local Python
environment and an exact immutable candidate reference:

```powershell
uv sync --all-extras --frozen
$imageName = "127.0.0.1:25001/astraldeep/lets"
$imageDigest = "sha256:336feda3da169ecffea8ab3f0b68858c5de304cafe2208ee696d714c6dab64c4"
$env:LETS_PRODUCTION_ACCEPTANCE_IMAGE = "$imageName@$imageDigest"
uv run --frozen python deploy/production/run_acceptance.py
```

The supplied production profile is admitted only on Linux/amd64 or Linux/arm64. Docker Desktop is
useful for smoke testing but is not a claimed production durability or failure boundary.

The executable bounded model uses the same local environment. The TLC runner uses preinstalled
Java, downloads its pinned JAR only below the ignored repository `tmp/` directory, verifies the
recorded digest and size, and installs no system software:

```powershell
uv run --frozen python -m formal.model_checker
powershell -NoProfile -File formal/run_tlc.ps1
```

The post-optimization microbenchmarks use the local environment and retain reviewed, host-specific
evidence under `benchmarks/baselines/`:

```powershell
uv run --frozen python -m benchmarks.run
uv run --frozen python -m benchmarks.profile_scaling
uv run --frozen python -m benchmarks.profile_invariants
uv run --frozen python -m benchmarks.profile_anchor
```

Before release, run `make paper-check`, inspect every PNG under `paper/build/render`, and verify
the final PDF metadata/page count independently. A successful LaTeX exit is not visual QA.

## Direct container command

If GNU Make is unavailable, run the equivalent command from the repository root, replacing the
source path with the absolute repository path:

```powershell
docker run --rm `
  --mount "type=bind,source=$((Get-Location).Path),target=/workspace" `
  --workdir /workspace/paper `
  texlive/texlive:latest-small@sha256:247724c3f35022a6e938044ee7ca5dad87841d14c651e7b22467ea62c1d84597 `
  sh -lc "mkdir -p build && latexmk paper.tex && cp build/paper.pdf lets.pdf"
```
