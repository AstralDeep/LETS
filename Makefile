# Docker-driven build for the LETS paper (paper/submission/manuscript.tex): renders the PDF via
# latexmk, then paper-check enforces page limits, no LaTeX warnings, and embedded fonts before
# submission.

PAPER_IMAGE ?= texlive/texlive:latest-small@sha256:247724c3f35022a6e938044ee7ca5dad87841d14c651e7b22467ea62c1d84597
PAPER_RENDER_IMAGE ?= minidocks/poppler:latest@sha256:93bc2829f994f5dee3b0927d5b4f3670db72e2b60d5b8544ef34418529cfa4e6

ifeq ($(OS),Windows_NT)
HOST_ROOT := $(shell cygpath -w "$(CURDIR)")
else
HOST_ROOT := $(CURDIR)
endif

PAPER_CONTAINER = docker run --rm --mount 'type=bind,source=$(HOST_ROOT),target=/workspace' --workdir /workspace/paper/submission $(PAPER_IMAGE)
PAPER_RENDER_CONTAINER = docker run --rm --mount 'type=bind,source=$(HOST_ROOT),target=/workspace' --workdir /workspace/paper/submission $(PAPER_RENDER_IMAGE)

.PHONY: paper paper-check paper-render paper-clean

paper:
	$(PAPER_CONTAINER) sh -lc 'mkdir -p build/manuscript /workspace/output/pdf && latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/manuscript manuscript.tex && cp build/manuscript/manuscript.pdf /workspace/output/pdf/lets.pdf'

paper-check: paper
	$(PAPER_CONTAINER) sh -lc 'test -s build/manuscript/manuscript.pdf && ! grep -E "LaTeX Warning:|Package .* Warning:|Overfull \\\\hbox|Citation.*undefined|Reference.*undefined" build/manuscript/manuscript.log && body=$$(sed -n "s/.*newlabel{LastBodyPage}{{[^}]*}{\\([0-9][0-9]*\\)}.*/\\1/p" build/manuscript/manuscript.aux) && intro=$$(sed -n "s/.*newlabel{IntroEndPage}{{[^}]*}{\\([0-9][0-9]*\\)}.*/\\1/p" build/manuscript/manuscript.aux) && test "$$body" -le 12 && test "$$intro" -le 3'
	$(PAPER_RENDER_CONTAINER) sh -lc 'test -z "$$(pdffonts build/manuscript/manuscript.pdf | tail -n +3 | grep -Ev yes.yes)"'

paper-render: paper
	$(PAPER_RENDER_CONTAINER) sh -lc 'mkdir -p build/render && pdftoppm -png -r 120 build/manuscript/manuscript.pdf build/render/page'

paper-clean:
	$(PAPER_CONTAINER) sh -lc 'rm -rf build/render build/manuscript && rm -f /workspace/output/pdf/lets.pdf'
