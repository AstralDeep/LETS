"""Drive the dashboard in a real browser and capture screenshots.

Dev tool for verifying the UI, not part of the demo itself.
"""

from __future__ import annotations

import os
import sys

from playwright.sync_api import sync_playwright

# Defaults to the dev dashboard; point it at :8801 to drive the production one.
URL = os.environ.get("LETS_DEMO_UI", "http://127.0.0.1:8800/")
OUT = "shots"

# One per scene in demo/static/delegation.html, in order.
SCENE_SHOTS = [
    "envelope",
    "escrow",
    "second-child",
    "over-allocation",
    "attenuation",
    "work",
    "drained",
]


def main() -> int:
    steps = sys.argv[1:] or ["full"]
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 1000}, device_scale_factor=2)
        errors: list[str] = []
        page.on("console", lambda m: errors.append(f"{m.type}: {m.text}") if m.type == "error" else None)
        page.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))

        page.goto(URL, wait_until="networkidle")

        def shot(name: str) -> None:
            page.screenshot(path=f"{OUT}/{name}.png", full_page=True)
            print(f"  wrote {OUT}/{name}.png")

        def click(sel: str, label: str) -> None:
            page.click(sel)
            page.wait_for_function(
                "() => !document.getElementById('busy').classList.contains('on')",
                timeout=60000,
            )
            page.wait_for_timeout(180)
            print(f"  clicked {label}")

        # Static pages only -- no warden traffic, for iterating on the
        # walkthrough without redriving the whole register.
        if "pages" in steps:
            for scene in range(len(SCENE_SHOTS)):
                page.goto(URL + "delegation", wait_until="networkidle")
                page.click("#b-play")
                page.click(f'#steps button[data-step="{scene}"]')
                page.wait_for_timeout(900)
                shot(f"1{scene}-delegation-{SCENE_SHOTS[scene]}")

        if "full" in steps:
            click("#b-reset", "reset") if not page.is_disabled("#b-reset") else None
            shot("01-empty")
            click("#b-root", "provision root")
            shot("02-root")
            click("#b-child", "delegate")
            click("#b-work", "research")
            click("#b-sum", "summarize")
            shot("03-working")
            click("#b-over", "oversized (denied)")
            click("#b-esc", "escalated (denied)")
            shot("04-denials")
            # select the child, delegate again to get depth 2, then drain it
            rows = page.query_selector_all("tbody tr")
            if len(rows) > 1:
                rows[1].click()
                page.wait_for_timeout(150)
                click("#b-child", "delegate from child")
                click("#b-drain", "drain")
            shot("05-deep")
            click("#b-reset", "reset")
            shot("06-reset")
            page.set_viewport_size({"width": 430, "height": 950})
            page.wait_for_timeout(200)
            shot("07-mobile")

            # the docs page
            page.set_viewport_size({"width": 1280, "height": 1000})
            page.goto(URL + "docs", wait_until="networkidle")
            shot("08-docs")
            page.set_viewport_size({"width": 430, "height": 950})
            page.wait_for_timeout(200)
            shot("09-docs-mobile")

            # the delegation walkthrough, stepped rather than left to autoplay
            # so the captured frames are deterministic
            page.set_viewport_size({"width": 1280, "height": 1000})
            page.goto(URL + "delegation", wait_until="networkidle")
            page.click("#b-play")  # pause the autoplay
            for scene in range(len(SCENE_SHOTS)):
                page.click(f'#steps button[data-step="{scene}"]')
                page.wait_for_timeout(900)
                shot(f"1{scene}-delegation-{SCENE_SHOTS[scene]}")
            page.set_viewport_size({"width": 430, "height": 950})
            page.wait_for_timeout(300)
            shot("17-delegation-mobile")

        browser.close()
        if errors:
            print("\nCONSOLE ERRORS:")
            for e in errors:
                print("  " + e)
            return 1
        print("\nno console errors")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
