"""Fetch a URL and return readable main text, truncated for the LLM.
~12k characters is roughly 3k tokens; enough for an 8-K or a news article."""
from __future__ import annotations

import logging
import re

from bs4 import BeautifulSoup

from sources import BROWSER_UA, _get

log = logging.getLogger("fetch_text")
logging.getLogger("trafilatura").setLevel(logging.CRITICAL)  # it shouts at every 8-K
MAX_CHARS = 12_000


def fetch_text(url: str) -> str | None:
    r = _get(url)
    if not r and "sec.gov" not in url:  # some news sites 403 non-browser agents
        r = _get(url, headers={"User-Agent": BROWSER_UA})
    if not r:
        return None
    html = r.text
    text = None
    try:
        import trafilatura

        text = trafilatura.extract(html, include_comments=False, include_tables=True)
    except Exception as e:  # noqa: BLE001
        log.debug("trafilatura failed on %s: %s", url, e)
    if not text:
        soup = BeautifulSoup(html, "lxml")
        for t in soup(["script", "style", "nav", "header", "footer", "aside"]):
            t.decompose()
        text = soup.get_text("\n", strip=True)
    text = re.sub(r"\n{3,}", "\n\n", text or "").strip()
    return text[:MAX_CHARS] if text else None
