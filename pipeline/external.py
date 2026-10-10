"""Context joined onto records at build time, kept out of the record schema:

- CISA KEV: when each CVE on a record was listed as exploited in the wild. Tries the
  CISA feed (US-only in practice), then NVD per CVE (slow: 6 s between calls, no key).
- Share prices for 8-K filers: daily closes from the Nasdaq data API for the ticker
  behind the filing's CIK, from a month before the filing to a year after, plus SPY
  for the market-adjusted return. One request per ticker per run; a series that already
  covers a year past the filing is not refetched.

    python pipeline/external.py            # both
    python pipeline/external.py --kev      # one
Writes data/external/kev.json and data/external/prices.json.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from datetime import date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import DATA_DIR, INCIDENTS_PATH, read_jsonl  # noqa: E402
from sources import BROWSER_UA, _get  # noqa: E402

log = logging.getLogger("external")
EXT_DIR = DATA_DIR / "external"
KEV_PATH, PRICES_PATH = EXT_DIR / "kev.json", EXT_DIR / "prices.json"
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TICKERS = "https://www.sec.gov/files/company_tickers.json"
NASDAQ = "https://api.nasdaq.com/api/quote/{sym}/historical"
PRICE_BEFORE, PRICE_AFTER = 35, 380  # calendar days around the filing
KEV_RECHECK_DAYS = 30
ALPHA = "https://www.alphavantage.co/query"  # free key, 25 requests/day: used only for filings the Nasdaq API no longer covers


def _load(path: Path) -> dict:
    return json.loads(path.read_text()) if path.exists() else {}


def _save(path: Path, obj: dict) -> None:
    EXT_DIR.mkdir(exist_ok=True)
    path.write_text(json.dumps(obj, indent=0, sort_keys=True))


# --- KEV ---------------------------------------------------------------------------
def update_kev(rows: list[dict]) -> dict:
    kev = _load(KEV_PATH)
    wanted = sorted({c.upper() for r in rows for c in (r.get("cve") or [])})
    today = date.today().isoformat()
    stale = (date.today() - timedelta(days=KEV_RECHECK_DAYS)).isoformat()
    # An unlisted CVE can be listed later, so unlisted entries are asked again periodically.
    missing = [c for c in wanted if c not in kev or (not kev[c].get("added") and (kev[c].get("checked") or "") < stale)]
    if not missing:
        return kev
    r = _get(KEV_FEED, headers={"User-Agent": BROWSER_UA})
    if r:
        for v in r.json().get("vulnerabilities", []):
            kev[v["cveID"]] = {"added": v["dateAdded"], "name": v.get("vulnerabilityName"),
                               "vendor": v.get("vendorProject"), "product": v.get("product"),
                               "ransomware": v.get("knownRansomwareCampaignUse")}
        for c in missing:
            kev.setdefault(c, {"added": None})
            kev[c]["checked"] = today
        log.info("kev: feed loaded, %d of %d wanted CVEs listed", sum(1 for c in wanted if kev[c].get("added")), len(wanted))
    else:
        log.info("kev: feed unavailable; asking NVD for %d CVEs", len(missing))
        for i, c in enumerate(missing):
            if i:
                time.sleep(6)
            n = _get(NVD_API, params={"cveId": c}, headers={"User-Agent": BROWSER_UA})
            if not n:
                continue
            vulns = n.json().get("vulnerabilities") or []
            v = vulns[0]["cve"] if vulns else {}
            kev[c] = {"added": v.get("cisaExploitAdd"), "name": v.get("cisaVulnerabilityName"),
                      "ransomware": None, "nvd_published": (v.get("published") or "")[:10] or None,
                      "checked": today}
    _save(KEV_PATH, kev)
    return kev


# --- prices -------------------------------------------------------------------------
def cik_of(rec: dict) -> int | None:
    for s in rec.get("sources", []):
        m = re.search(r"/edgar/data/(\d+)/", s["url"]) if s["type"] == "sec_8k" else None
        if m:
            return int(m.group(1))
    return None


def ticker_map() -> dict[int, str]:
    import os
    ua = os.environ.get("EDGAR_USER_AGENT") or "breach-tracker admin@example.com"
    r = _get(TICKERS, headers={"User-Agent": ua})
    return {v["cik_str"]: v["ticker"] for v in r.json().values()} if r else {}


def nasdaq_closes(sym: str, start: date, end: date, asset: str = "stocks") -> dict[str, float]:
    r = _get(NASDAQ.format(sym=sym), params={"assetclass": asset, "fromdate": start.isoformat(),
                                             "todate": end.isoformat(), "limit": 9999},
             headers={"User-Agent": BROWSER_UA, "Accept": "application/json"})
    if not r:
        return {}
    rows = ((r.json().get("data") or {}).get("tradesTable") or {}).get("rows") or []
    out = {}
    for x in rows:
        try:
            out[datetime.strptime(x["date"], "%m/%d/%Y").date().isoformat()] = float(x["close"].replace("$", "").replace(",", ""))
        except (KeyError, ValueError):
            continue
    return out


def alpha_closes(sym: str, key: str) -> dict[str, float]:
    r = _get(ALPHA, params={"function": "TIME_SERIES_DAILY", "symbol": sym, "outputsize": "full", "apikey": key})
    if not r:
        return {}
    series = r.json().get("Time Series (Daily)") or {}
    if not series:
        log.info("alpha vantage: no series for %s (%s)", sym, (r.json().get("Information") or r.json().get("Note") or "")[:80])
    return {d: float(v["4. close"]) for d, v in series.items()}


def cur_tried_nasdaq(cur: dict | None) -> bool:
    return bool((cur or {}).get("tried_nasdaq"))


def covers(series: dict | None, filed: str) -> bool:
    closes = (series or {}).get("closes") or {}
    return bool(closes) and min(closes) < filed


def update_prices(rows: list[dict]) -> dict:
    import os
    prices = _load(PRICES_PATH)
    today = date.today()
    filers = [(r, cik_of(r)) for r in rows if not r.get("imported_from")]
    filers = [(r, c) for r, c in filers if c]
    if not filers:
        return prices
    tickers = ticker_map()
    spy = prices.get("_SPY", {})
    need_spy_from = min(date.fromisoformat(r["disclosed_date"]) for r, _ in filers) - timedelta(days=PRICE_BEFORE)
    if not spy or min(spy) > need_spy_from.isoformat() or max(spy) < (today - timedelta(days=4)).isoformat():
        got = nasdaq_closes("SPY", need_spy_from, today, "etf")
        if got:
            spy.update(got)
            prices["_SPY"] = spy
    fetched, alpha_left = 0, 25 if os.environ.get("ALPHAVANTAGE_API_KEY") else 0
    for r, cik in filers:
        cur = prices.get(r["id"])
        filed = date.fromisoformat(r["disclosed_date"])
        fresh = cur and cur.get("closes") and max(cur["closes"]) >= (today - timedelta(days=4)).isoformat()
        if cur and covers(cur, filed.isoformat()) and (cur.get("complete") or fresh):
            if not cur.get("complete") and filed + timedelta(days=PRICE_AFTER) < today:
                cur["complete"] = True
            continue
        sym = tickers.get(cik) or (cur or {}).get("ticker")
        if not sym:
            prices[r["id"]] = {"cik": cik, "ticker": None}
            continue
        start, end = filed - timedelta(days=PRICE_BEFORE), min(today, filed + timedelta(days=PRICE_AFTER))
        closes = dict((cur or {}).get("closes") or {})
        # Nasdaq is asked when the series never covered the filing, and again whenever an
        # unfinished series has gone stale, so the later horizons fill in over the year.
        if not (covers(cur, filed.isoformat()) and cur_tried_nasdaq(cur)) or not fresh:
            closes.update(nasdaq_closes(sym, start, end))
            fetched += 1
            time.sleep(0.5)
        if (not closes or min(closes) > filed.isoformat()) and alpha_left:
            # Nasdaq's API keeps roughly 18 months; older filings need another source.
            alpha_left -= 1
            full = alpha_closes(sym, os.environ["ALPHAVANTAGE_API_KEY"])
            closes = {d: c for d, c in full.items() if start.isoformat() <= d <= end.isoformat()} or closes
            fetched += 1
        prices[r["id"]] = {"cik": cik, "ticker": sym, "filed": filed.isoformat(), "closes": closes,
                           "tried_nasdaq": True,
                           "complete": filed + timedelta(days=PRICE_AFTER) < today and covers({"closes": closes}, filed.isoformat())}
    log.info("prices: %d filers, %d series fetched this run", len(filers), fetched)
    _save(PRICES_PATH, prices)
    return prices


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kev", action="store_true")
    ap.add_argument("--prices", action="store_true")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    rows = read_jsonl(INCIDENTS_PATH)
    both = not (args.kev or args.prices)
    if args.kev or both:
        update_kev(rows)
    if args.prices or both:
        update_prices(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
