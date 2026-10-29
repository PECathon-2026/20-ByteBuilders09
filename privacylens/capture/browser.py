"""
PrivacyLens - Playwright Browser Controller
Manages browser initialization, navigation, and local DOM automation.
"""

from typing import Optional, Dict, Any
from playwright.sync_api import sync_playwright, Browser, Page, Playwright


class BrowserController:
    def __init__(self, headless: bool = True):
        self.headless = headless
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._page: Optional[Page] = None

    def is_alive(self) -> bool:
        try:
            return bool(
                self._browser and self._browser.is_connected() and 
                self._page and not self._page.is_closed()
            )
        except Exception:
            return False

    def start(self):
        """Launches Chromium instance."""
        try:
            if not self._browser or not self._browser.is_connected():
                if self._playwright:
                    try:
                        self._playwright.stop()
                    except Exception:
                        pass
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(
                    headless=self.headless,
                    args=["--disable-web-security", "--no-sandbox"]
                )
            if not self._page or self._page.is_closed():
                self._page = self._browser.new_page(viewport={"width": 1280, "height": 800})
            return self._page
        except Exception:
            # Full reset fallback
            self.close()
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=self.headless,
                args=["--disable-web-security", "--no-sandbox"]
            )
            self._page = self._browser.new_page(viewport={"width": 1280, "height": 800})
            return self._page

    def get_page(self) -> Page:
        if not self.is_alive():
            self.start()
        return self._page

    def new_page(self) -> Page:
        if not self._browser or not self._browser.is_connected():
            self.start()
        return self._browser.new_page(viewport={"width": 1280, "height": 800})

    def navigate(self, url: str):
        """Navigates to URL and waits for DOM content to settle."""
        page = self.get_page()
        page.goto(url, wait_until="load", timeout=15000)
        page.wait_for_timeout(400)
        return page

    def close(self):
        """Closes browser session."""
        try:
            if self._page and not self._page.is_closed():
                self._page.close()
        except Exception:
            pass
        self._page = None

        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        self._browser = None

        try:
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        self._playwright = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
