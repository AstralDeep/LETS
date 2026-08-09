PAPER_IMAGE ?= texlive/texlive:latest-small@sha256:247724c3f35022a6e938044ee7ca5dad87841d14c651e7b22467ea62c1d84597
PAPER_RENDER_IMAGE ?= minidocks/poppler:latest@sha256:93bc2829f994f5dee3b0927d5b4f3670db72e2b60d5b8544ef34418529cfa4e6

ifeq ($(OS),Windows_NT)
HOST_ROOT := $(shell cygpath -w "$(CURDIR)")
else
HOST_ROOT := $(CURDIR)
endif

PAPER_CONTAINER = docker run --rm --mount 'type=bind,source=$(HOST_ROOT),target=/workspace' --workdir /workspace/paper $(PAPER_IMAGE)
PAPER_RENDER_CONTAINER = docker run --rm --mount 'type=bind,source=$(HOST_ROOT),target=/workspace' --workdir /workspace/paper $(PAPER_RENDER_IMAGE)

.PHONY: paper paper-check paper-render paper-clean

paper:
	$(PAPER_CONTAINER) sh -lc 'mkdir -p build && latexmk paper.tex && cp build/paper.pdf lets.pdf'

paper-check: paper
	$(PAPER_CONTAINER) sh -lc 'test -s lets.pdf && ! grep -E "LaTeX Warning:|Overfull \\\\hbox|Citation.*undefined|Reference.*undefined" build/paper.log'
	$(PAPER_RENDER_CONTAINER) sh -lc 'pdfinfo lets.pdf > build/pdfinfo.txt && grep -q "PDF version:" build/pdfinfo.txt'

paper-render: paper
	$(PAPER_RENDER_CONTAINER) sh -lc 'rm -rf build/render && mkdir -p build/render && pdftoppm -png -r 120 lets.pdf build/render/page'

paper-clean:
	$(PAPER_CONTAINER) sh -lc 'rm -rf build lets.pdf'
