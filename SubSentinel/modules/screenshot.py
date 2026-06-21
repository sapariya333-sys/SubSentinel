"""
modules/screenshot.py - Playwright-based screenshot capture
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional

from core.config import ScanConfig

logger = logging.getLogger(__name__)


class ScreenshotEngine:
    """Capture screenshots of vulnerable subdomains using Playwright."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.screenshots_dir = Path(config.output_dir) / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self._playwright = None
        self._browser = None

    async def _ensure_browser(self):
        """Initialize Playwright browser lazily."""
        if self._browser:
            return

        try:
            from playwright.async_api import async_playwright
            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--no-first-run",
                    "--no-zygote",
                    "--single-process",
                ]
            )
            logger.debug("Playwright browser initialized")
        except ImportError:
            logger.warning("Playwright not installed. Screenshots disabled.")
            self._browser = None
        except Exception as e:
            logger.warning(f"Failed to initialize Playwright browser: {e}")
            self._browser = None

    async def capture(self, hostname: str) -> Optional[Path]:
        """Capture screenshot of a hostname."""
        if self.config.no_screenshot:
            return None

        await self._ensure_browser()

        if not self._browser:
            return None

        screenshot_path = self.screenshots_dir / f"{hostname.replace('/', '_')}.png"

        try:
            context = await self._browser.new_context(
                viewport={"width": 1280, "height": 720},
                user_agent=self.config.user_agent,
                ignore_https_errors=True,
            )

            if self.config.proxy:
                # Proxy via browser context
                context = await self._browser.new_context(
                    proxy={"server": self.config.proxy},
                    viewport={"width": 1280, "height": 720},
                    ignore_https_errors=True,
                )

            page = await context.new_page()

            # Try HTTPS first, fall back to HTTP
            for scheme in ("https", "http"):
                try:
                    await page.goto(
                        f"{scheme}://{hostname}",
                        wait_until="networkidle",
                        timeout=15000
                    )
                    await page.screenshot(
                        path=str(screenshot_path),
                        full_page=False,
                        type="png"
                    )
                    await context.close()
                    logger.debug(f"Screenshot saved: {screenshot_path}")
                    return screenshot_path
                except Exception as e:
                    logger.debug(f"Screenshot attempt failed ({scheme}://{hostname}): {e}")
                    continue

            await context.close()

        except Exception as e:
            logger.debug(f"Screenshot capture failed for {hostname}: {e}")

        return None

    async def close(self):
        """Close the browser and Playwright."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
