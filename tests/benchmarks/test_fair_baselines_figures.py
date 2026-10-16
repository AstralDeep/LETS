"""Figure output tests for the E1 harness: SVG figures are written with LF line endings on every
platform so the evidence manifest digests match the files Git stores.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from benchmarks.fair_baselines.figures import save_figure


def test_svg_figures_use_lf_line_endings_and_pdf_still_saves(tmp_path: Path) -> None:
    fig, axis = plt.subplots()
    axis.plot([0, 1], [0, 1])
    save_figure(fig, tmp_path / "nested" / "plot.svg")
    raw = (tmp_path / "nested" / "plot.svg").read_bytes()
    assert raw.startswith(b"<?xml") and b"\r" not in raw and b"</svg>" in raw
    fig, axis = plt.subplots()
    axis.plot([0, 1], [1, 0])
    save_figure(fig, tmp_path / "plot.pdf")
    assert (tmp_path / "plot.pdf").read_bytes().startswith(b"%PDF")
