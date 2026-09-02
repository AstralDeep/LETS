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
	$(PAPER_CONTAINER) sh -lc 'mkdir -p build/arxiv build/nsdi /workspace/output/pdf && latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/arxiv paper-arxiv.tex && latexmk -pdf -interaction=nonstopmode -halt-on-error -outdir=build/nsdi paper-nsdi27.tex && cp build/arxiv/paper-arxiv.pdf /workspace/output/pdf/lets-arxiv.pdf && cp build/nsdi/paper-nsdi27.pdf /workspace/output/pdf/submission-nsdi27.pdf'

paper-check: paper
	$(PAPER_CONTAINER) sh -lc 'test -s build/arxiv/paper-arxiv.pdf && test -s build/nsdi/paper-nsdi27.pdf && ! grep -E "LaTeX Warning:|Package .* Warning:|Overfull \\\\hbox|Citation.*undefined|Reference.*undefined" build/arxiv/paper-arxiv.log build/nsdi/paper-nsdi27.log && body=$$(sed -n "s/.*newlabel{LastBodyPage}{{[^}]*}{\\([0-9][0-9]*\\)}.*/\\1/p" build/nsdi/paper-nsdi27.aux) && intro=$$(sed -n "s/.*newlabel{IntroEndPage}{{[^}]*}{\\([0-9][0-9]*\\)}.*/\\1/p" build/nsdi/paper-nsdi27.aux) && test "$$body" -le 12 && test "$$intro" -le 3'
	$(PAPER_RENDER_CONTAINER) sh -lc 'pdftotext -layout build/nsdi/paper-nsdi27.pdf /tmp/nsdi.txt && grep -q "Anonymous authors" /tmp/nsdi.txt && ! grep -E "LETS|AstralDeep|AstralPlane|Kentucky|Louisville|v1\\.0\\.11|feature-074|src/lets|kyopen" /tmp/nsdi.txt && test -z "$$(pdffonts build/arxiv/paper-arxiv.pdf | tail -n +3 | grep -Ev yes.yes)" && test -z "$$(pdffonts build/nsdi/paper-nsdi27.pdf | tail -n +3 | grep -Ev yes.yes)"'

paper-render: paper
	$(PAPER_RENDER_CONTAINER) sh -lc 'mkdir -p build/render-arxiv build/render-nsdi && pdftoppm -png -r 120 build/arxiv/paper-arxiv.pdf build/render-arxiv/page && pdftoppm -png -r 120 build/nsdi/paper-nsdi27.pdf build/render-nsdi/page'

paper-clean:
	$(PAPER_CONTAINER) sh -lc 'rm -rf build/render-arxiv build/render-nsdi build/arxiv build/nsdi && rm -f /workspace/output/pdf/lets-arxiv.pdf /workspace/output/pdf/submission-nsdi27.pdf'
