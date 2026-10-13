"""Source fetchers. Each returns a list of *candidates*: dicts with at least
org_name (may be "" for news items), disclosed_date, source_type, source_url.
Everything here is best-effort and defensive: a broken source logs and returns [],
it never kills the run.

Candidate shape:
    {
      "org_name": str,                 # "" if the LLM must identify it from text
      "disclosed_date": "YYYY-MM-DD",
      "source_type": str,              # enum in schema.sources[].type
      "source_url": str,               # unique per candidate; the queue is keyed on it
      "title": str | None,
      "text": str | None,              # narrative text if the source carries it
      "structured_hint": dict,         # regulator fields, leak-site fields, 8-K items
      "evidence_level_hint": str,      # schema.evidence_level
      "org_country": str,              # ISO2 or "unknown"
    }
"""
from __future__ import annotations

import csv
import io
import logging
import os
import json
import re
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup

from common import USER_AGENT

log = logging.getLogger("sources")
S = requests.Session()
S.headers["User-Agent"] = USER_AGENT
# Some sites (Hackmageddon, the HHS portal) refuse anything that doesn't look like a browser.
BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/130.0 Safari/537.36")
TIMEOUT = 30


def _get(url: str, **kw) -> requests.Response | None:
    try:
        r = S.get(url, timeout=kw.pop("timeout", TIMEOUT), **kw)
        r.raise_for_status()
        return r
    except Exception as e:  # noqa: BLE001
        # requests puts the full URL, query string included, in its messages; keys live there.
        log.warning("GET %s failed: %s", url, re.sub(r"\?[^\s'\"]*", "?…", str(e)))
        return None


def _iso(d: str | None) -> str | None:
    """Parse the handful of date formats regulators use; return ISO or None."""
    if not d:
        return None
    d = d.strip()
    for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%m-%d-%Y", "%m/%d/%y", "%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(d[:20].split(" and ")[0].strip(), fmt).date().isoformat()
        except ValueError:
            continue
    m = re.search(r"(\d{4}-\d{2}-\d{2})", d)
    return m.group(1) if m else None


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:80]


# ---------------------------------------------------------------------------
# 1. SEC EDGAR full-text search (free, JSON, no key; needs descriptive User-Agent)
# ---------------------------------------------------------------------------
EFTS = "https://efts.sec.gov/LATEST/search-index"


def _edgar_hit(hit: dict, default_date: str) -> dict | None:
    src = hit.get("_source", {})
    adsh, _, fname = hit.get("_id", "::").partition(":")
    ciks = src.get("ciks") or []
    names = src.get("display_names") or []
    if not (adsh and fname and ciks and names):
        return None
    return {
        "org_name": re.sub(r"\s+\(.*$", "", names[0]).strip(),
        "disclosed_date": src.get("file_date", default_date),
        "source_type": "sec_8k",
        "source_url": f"https://www.sec.gov/Archives/edgar/data/{int(ciks[0])}/{adsh.replace('-', '')}/{fname}",
        "title": f"8-K {src.get('file_description') or ''}".strip(),
        "text": None,  # fetched later
        "structured_hint": {"items": src.get("items"), "sic": src.get("sics"),
                            "state": src.get("biz_states"),
                            "exhibit": bool(re.search(r"ex(h|hibit)?[-_]?\d", fname, re.I))},
        "evidence_level_hint": "org_confirmed",
        "org_country": "US",
    }


def sec_edgar(since: date, until: date) -> list[dict]:
    """8-Ks mentioning a cybersecurity incident. Do NOT filter on Item 1.05 only:
    most disclosures land under 8.01 or 7.01. Hits are per file, so one filing can
    yield the main document plus its exhibits; dedupe collapses them."""
    if "EDGAR_USER_AGENT" not in os.environ:
        log.warning("EDGAR_USER_AGENT not set; www.sec.gov returns 403 unless the User-Agent carries a contact email")
    params = {"q": '"cybersecurity incident"', "forms": "8-K",
              "startdt": since.isoformat(), "enddt": until.isoformat()}
    r = _get(EFTS, params=params)
    if not r:
        return []
    out = [c for c in (_edgar_hit(h, until.isoformat()) for h in r.json().get("hits", {}).get("hits", [])) if c]
    log.info("sec_edgar: %d candidates", len(out))
    return out


# ---------------------------------------------------------------------------
# 2. HHS OCR breach portal (public domain). The portal is a JSF app: GET the front
#    page, "click" View HIPAA Breach Reports, then "click" the CSV export icon. The
#    export is the last 24 months of open cases (~750 rows), newest first.
#    HHS_CSV_URL (URL or local path) short-circuits all of that.
# ---------------------------------------------------------------------------
HHS_PORTAL = "https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf"
HHS_COLUMNS = ["Name of Covered Entity", "State", "Covered Entity Type", "Individuals Affected",
               "Breach Submission Date", "Type of Breach", "Location of Breached Information",
               "Business Associate Present", "Web Description"]


def _jsf_click(sess: requests.Session, soup: BeautifulSoup, page_url: str, *,
               link_text: str | None = None, img_title: str | None = None) -> requests.Response:
    """Submit the ocrForm the way the page's onclick handler would."""
    form = soup.find("form", id="ocrForm")
    if link_text:
        a = next(a for a in soup.select("a[onclick]") if link_text.lower() in a.get_text(" ", strip=True).lower())
    else:
        a = soup.find("img", title=img_title).find_parent("a")
    button = re.search(r"\{'(ocrForm:[^']+)'", a["onclick"]).group(1)
    data = {i["name"]: i.get("value", "") for i in form.find_all("input") if i.get("name")}
    data[button] = button
    r = sess.post(requests.compat.urljoin(page_url, form["action"]), data=data, timeout=180)
    r.raise_for_status()
    return r


def _hhs_csv_rows(text: str) -> list[dict]:
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        return rows
    # The export names two columns after their JSF component ("javax.faces...UIPanel@...");
    # recover them by position.
    headers = list(rows[0].keys())
    if len(headers) == len(HHS_COLUMNS):
        rename = {h: HHS_COLUMNS[i] for i, h in enumerate(headers) if h.startswith("javax.faces")}
        rows = [{rename.get(k, k): v for k, v in r.items()} for r in rows]
    return rows


def hhs_rows() -> list[dict]:
    src = os.environ.get("HHS_CSV_URL")
    if src and not src.startswith("http"):
        return _hhs_csv_rows(Path(src).read_text(encoding="utf-8-sig"))
    if src:
        r = _get(src)
        return _hhs_csv_rows(r.content.decode("utf-8-sig", "replace")) if r else []
    sess = requests.Session()
    sess.headers["User-Agent"] = BROWSER_UA
    try:
        r = sess.get(HHS_PORTAL, timeout=TIMEOUT)
        r.raise_for_status()
        r = _jsf_click(sess, BeautifulSoup(r.text, "lxml"), r.url, link_text="View HIPAA Breach Reports")
        page = BeautifulSoup(r.text, "lxml")
        try:
            exp = _jsf_click(sess, page, r.url, img_title="Export as CSV")
            if "csv" in exp.headers.get("content-type", ""):
                return _hhs_csv_rows(exp.content.decode("utf-8-sig", "replace"))
            log.warning("hhs: CSV export returned %s; falling back to the HTML table", exp.headers.get("content-type"))
        except Exception as e:  # noqa: BLE001
            log.warning("hhs: CSV export failed (%s); falling back to the HTML table", e)
        table = next((t for t in page.find_all("table") if t.find("th")), None)
        if not table:
            return []
        headers = [th.get_text(" ", strip=True) for th in table.find_all("th")]
        rows = []
        for tr in table.find_all("tr")[1:]:
            cells = [td.get_text(" ", strip=True) for td in tr.find_all("td")]
            if len(cells) >= len(headers):
                rows.append(dict(zip(headers, cells)))
        return rows
    except Exception as e:  # noqa: BLE001
        log.warning("hhs: portal fetch failed: %s", e)
        return []


def hhs(since: date) -> list[dict]:
    out: list[dict] = []
    for row in hhs_rows():
        name = (row.get("Name of Covered Entity") or "").strip()
        submitted = _iso(row.get("Breach Submission Date"))
        if not (name and submitted) or date.fromisoformat(submitted) < since:
            continue
        out.append({
            "org_name": name,
            "disclosed_date": submitted,
            "source_type": "hhs_portal",
            # One portal URL for every row; the fragment keeps queue keys unique.
            "source_url": f"{HHS_PORTAL}#{submitted}-{_slug(name)}",
            "title": "HHS OCR breach report",
            "text": row.get("Web Description") or None,
            "structured_hint": {
                "covered_entity_type": row.get("Covered Entity Type"),
                "individuals_affected": row.get("Individuals Affected"),
                "breach_type": row.get("Type of Breach"),
                "location": row.get("Location of Breached Information"),
                "business_associate_present": row.get("Business Associate Present"),
                "state": row.get("State"),
            },
            "evidence_level_hint": "regulator_filing",
            "org_country": "US",
        })
    log.info("hhs: %d candidates", len(out))
    return out


# ---------------------------------------------------------------------------
# 3. Maine AG data breach notices (public record; HTML pages, label: value).
#    maine.gov serves the notice list only to US addresses (elsewhere: 403 or a
#    redirect to a generic page), so this works from GitHub's runners but may not
#    work from a laptop abroad. Field labels verified April 2026.
# ---------------------------------------------------------------------------
MAINE_DIR = "https://www.maine.gov/agviewer/content/ag/985235c7-cb95-4be2-8792-a1252b4f8318/"
MAINE_INDEX = MAINE_DIR + "list.html"


def maine_ag(since: date, max_pages: int = 150) -> list[dict]:
    out: list[dict] = []
    r = _get(MAINE_INDEX, headers={"User-Agent": BROWSER_UA})
    if not r or not r.url.startswith(MAINE_DIR):
        log.warning("maine_ag: index unavailable from this network (status %s, landed on %s)",
                    r.status_code if r else None, r.url if r else None)
        return out
    soup = BeautifulSoup(r.text, "lxml")
    links: list[str] = []
    for a in soup.find_all("a", href=True):
        url = requests.compat.urljoin(MAINE_INDEX, a["href"])
        if url.startswith(MAINE_DIR) and re.search(r"/[0-9a-f-]{36}\.s?html$", url) and url not in links:
            links.append(url)
    for url in links[:max_pages]:
        p = _get(url, headers={"User-Agent": BROWSER_UA})
        c = parse_maine_notice(p.text, url) if p else None
        if c and date.fromisoformat(c["disclosed_date"]) >= since:
            out.append(c)
        time.sleep(0.5)
    log.info("maine_ag: %d candidates", len(out))
    return out


def parse_maine_notice(html: str, url: str) -> dict | None:
    """One notice page -> candidate. The page is 'Label:' lines with the value on the
    next line; the labels below were verified against a 2026 notice. Also used by
    backfill --maine-zip on pages fetched elsewhere."""
    text = BeautifulSoup(html, "lxml").get_text("\n", strip=True)
    fields = dict(re.findall(r"^([A-Za-z][^:\n]{3,80}):\s*(.*)$", text, re.M))
    name = (fields.get("Entity Name") or "").strip()
    if not name:
        return None
    disclosed = (_iso(fields.get("Date(s) of consumer notification"))
                 or _iso(fields.get("Date Breach Discovered")) or date.today().isoformat())
    return {
        "org_name": name,
        "disclosed_date": disclosed,
        "source_type": "state_ag",
        "source_url": url,
        "title": "Maine AG data breach notice",
        "text": text[:6000],
        "structured_hint": {
            "org_type_raw": fields.get("Type of Organization"),
            "breach_description": fields.get("Description of the Breach"),
            "persons_affected": fields.get("Total number of persons affected (including residents)"),
            "date_occurred": fields.get("Date(s) Breach Occured"),
            "date_discovered": fields.get("Date Breach Discovered"),
            "information_acquired": next((v for k, v in fields.items() if k.startswith("Information Acquired")), None),
            "state": fields.get("State, or Country if outside the US"),
        },
        "evidence_level_hint": "regulator_filing",
        "org_country": "US",
    }


# ---------------------------------------------------------------------------
# 3a. Texas AG (oag.my.site.com, a Salesforce site). The page loads its rows with one
#     Visualforce remoting call that returns about 18 months of filings. Reachable
#     from outside the US (checked October 2026). No letters, no per-row page.
TX_PAGE = "https://oag.my.site.com/datasecuritybreachreport/apex/DataSecurityReportsPage"
TX_REMOTE = "https://oag.my.site.com/datasecuritybreachreport/apexremote"
TX_ORG_TYPE = {
    "Healthcare": "healthcare", "Financial Services": "financial", "Insurance Services": "financial",
    "Educational Institution": "education", "Governmental Entity": "government",
    "Business": "retail_ecommerce", "Nonprofit Organization": "nonprofit", "Other": "other",
}


def _epoch_day(ms) -> str | None:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).date().isoformat() if ms else None


def texas_candidates(rows: list[dict], since: date | None = None) -> list[dict]:
    out = []
    for r in rows:
        name = short_org(r.get("Business_Name__c") or "")
        published = _epoch_day(r.get("Published_at_AG_website_Date__c"))
        if not name or not published or (since and published < since.isoformat()):
            continue
        kind = (r.get("Type_of_Entity__c") or "").split("\u2013")[0].split("-")[0].strip()
        out.append({
            "org_name": name, "disclosed_date": published, "source_type": "state_ag",
            "source_url": f"{TX_PAGE}#{r.get('Name')}",
            "title": "Texas AG data security breach report", "text": None,
            "structured_hint": {
                "org_type_raw": kind,
                "persons_affected": r.get("Total_Number_of_Individuals_Affected__c") or r.get("Number_of_Texans_affected_by_the_breach__c"),
                "date_occurred": _epoch_day(r.get("Start_Breach_Date__c")),
                "date_discovered": _epoch_day(r.get("Breach_Discovered_Date__c")),
                "information_acquired": r.get("Types_of_Personal_Information_Involved__c"),
                "state": r.get("State_withTer__c"),
            },
            "evidence_level_hint": "regulator_filing", "org_country": "US",
        })
    return out


def texas_ag(since: date) -> list[dict]:
    """Fetch the page for its one-time remoting tokens, then call the data method."""
    page = _get(TX_PAGE, headers={"User-Agent": BROWSER_UA})
    m = re.search(r"RemotingProviderImpl\((\{)", page.text) if page else None
    if not m:
        log.warning("texas_ag: page unavailable or changed (status %s)", page.status_code if page else None)
        return []
    cfg = json.JSONDecoder().raw_decode(page.text[m.start(1):])[0]
    method = cfg["actions"]["DataSecurityReports"]["ms"][0]
    body = {"action": "DataSecurityReports", "method": "getDatareports", "data": [True], "type": "rpc", "tid": 2,
            "ctx": {"csrf": method["csrf"], "vid": cfg["vf"]["vid"], "ns": "", "ver": method["ver"],
                    "authorization": method["authorization"]}}
    try:
        r = requests.post(TX_REMOTE, json=body, timeout=120,
                          headers={"User-Agent": BROWSER_UA, "Referer": TX_PAGE})
        r.raise_for_status()
        rows = r.json()[0]["result"]
    except Exception as e:  # noqa: BLE001
        log.warning("texas_ag: remoting call failed: %s", e)
        return []
    out = texas_candidates(rows, since)
    log.info("texas_ag: %d candidates of %d rows", len(out), len(rows))
    return out


# ---------------------------------------------------------------------------
# 3b. California AG (oag.ca.gov/privacy/databreach/list). A Drupal table: organization,
#     date(s) of breach, date reported; 50 rows a page, newest first, ~107 pages back
#     to 2012. The detail page adds only the sample notice PDF. Reachable from
#     outside the US.
CA_LIST = "https://oag.ca.gov/privacy/databreach/list"


_ORG_TAIL = re.compile(r"\s*(?:,\s*)?(?:including|on behalf of|\(formerly|d/b/a|dba)\b.*$|\s+-\s+.*$", re.I)


def short_org(name: str) -> str:
    """Filers sometimes list every affiliate in the name field; keep the first entity."""
    cut = _ORG_TAIL.sub("", name).strip(" ,")
    return (cut or name)[:200]


def parse_ca_list(html: str) -> list[dict]:
    soup = BeautifulSoup(html, "lxml")
    out = []
    for tr in soup.select("table tbody tr"):
        tds = tr.find_all("td")
        if len(tds) < 3:
            continue
        a = tds[0].find("a", href=True)
        name = short_org(tds[0].get_text(" ", strip=True))
        if not (a and name):
            continue
        breach_dates = [d.strip() for d in tds[1].get_text(" ", strip=True).split(",") if d.strip()]
        reported = _iso(tds[2].get_text(" ", strip=True))
        if not reported:
            continue
        out.append({
            "org_name": name, "disclosed_date": reported, "source_type": "state_ag",
            "source_url": requests.compat.urljoin(CA_LIST, a["href"]),
            "title": "California AG data breach report", "text": None,
            "structured_hint": {"date_occurred": breach_dates[0] if breach_dates else None,
                                "date_occurred_all": breach_dates, "state": "CA"},
            "evidence_level_hint": "regulator_filing", "org_country": "US",
        })
    return out


def california_ag(since: date, max_pages: int = 3) -> list[dict]:
    out: list[dict] = []
    for page in range(max_pages):
        r = _get(CA_LIST, params={"page": page} if page else None, headers={"User-Agent": BROWSER_UA})
        if not r:  # the site throttles bursts; wait once, then give up for this run
            time.sleep(20)
            r = _get(CA_LIST, params={"page": page} if page else None, headers={"User-Agent": BROWSER_UA})
        if not r:
            log.warning("california_ag: page %d unavailable; stopping (re-run to continue)", page)
            break
        rows = parse_ca_list(r.text)
        if not rows:
            break
        out += [c for c in rows if date.fromisoformat(c["disclosed_date"]) >= since]
        if date.fromisoformat(rows[-1]["disclosed_date"]) < since:
            break
        time.sleep(2)
    log.info("california_ag: %d candidates", len(out))
    return out


# ---------------------------------------------------------------------------
# 3b2. Washington, Oregon and South Carolina publish HTML tables of breach reports.
#      Washington and South Carolina link the consumer letter; Oregon gives dates only.
#      Oregon and South Carolina answer US addresses only.
WA_LIST = "https://www.atg.wa.gov/data-breach-notifications"
OR_LIST = "https://justice.oregon.gov/consumer/DataBreach/"
SC_LIST = "https://consumer.sc.gov/identity-theft-unit/security-breach-notices"


def _state_row(name: str, reported: str | None, url: str, state: str, title: str, hint: dict) -> dict | None:
    name = short_org(name)
    if not (name and reported):
        return None
    return {"org_name": name, "disclosed_date": reported, "source_type": "state_ag", "source_url": url,
            "title": title, "text": None, "structured_hint": dict(hint, state=state),
            "evidence_level_hint": "regulator_filing", "org_country": "US"}


def _rows(html: str, min_cells: int):
    for tr in BeautifulSoup(html, "lxml").select("table tr"):
        tds = tr.find_all("td")
        if len(tds) >= min_cells:
            yield tds


def _anchor_url(td, base: str) -> str | None:
    a = td.find("a", href=True)
    return requests.compat.urljoin(base, a["href"]) if a else None


def _frag(base: str, name: str, reported: str) -> str:
    return f"{base}#{requests.utils.quote(name)}-{reported}"


def parse_wa_list(html: str) -> list[dict]:
    """Columns: date reported, organization (letter link), date of breach, Washingtonians affected, information compromised."""
    out = []
    for tds in _rows(html, 5):
        name, reported = tds[1].get_text(" ", strip=True), _iso(tds[0].get_text(" ", strip=True))
        url = _anchor_url(tds[1], WA_LIST) or _frag(WA_LIST, name, reported or "")
        c = _state_row(name, reported, url, "WA", "Washington AG data breach notification",
                       {"date_occurred": _iso(tds[2].get_text(" ", strip=True)), "persons_affected": tds[3].get_text(" ", strip=True),
                        "information_acquired": tds[4].get_text(" ", strip=True), "letter_url": url if url.lower().endswith(".pdf") else None})
        if c:
            out.append(c)
    return out


def parse_or_list(html: str) -> list[dict]:
    """Columns: organization, reported date, dates of breach, dates of discovery, date notice sent, number affected."""
    out = []
    for tds in _rows(html, 6):
        name, reported = tds[0].get_text(" ", strip=True), _iso(tds[1].get_text(" ", strip=True))
        first = lambda td: _iso(td.get_text(" ", strip=True).split("-")[0])  # noqa: E731  "6/30/2026 - 8/20/2026"
        c = _state_row(name, reported, _frag(OR_LIST, name, reported or ""), "OR", "Oregon DOJ data breach report",
                       {"date_occurred": first(tds[2]), "date_discovered": first(tds[3]), "persons_affected": tds[5].get_text(" ", strip=True)})
        if c:
            out.append(c)
    return out


def parse_sc_list(html: str) -> list[dict]:
    """Columns: organization (letter link), date reported, affected SC residents."""
    out = []
    for tds in _rows(html, 3):
        name, reported = tds[0].get_text(" ", strip=True), _iso(tds[1].get_text(" ", strip=True))
        url = _anchor_url(tds[0], SC_LIST) or _frag(SC_LIST, name, reported or "")
        c = _state_row(name, reported, url, "SC", "South Carolina consumer affairs breach notice",
                       {"persons_affected": tds[2].get_text(" ", strip=True), "letter_url": url if url.lower().endswith(".pdf") else None})
        if c:
            out.append(c)
    return out


VT_LIST = "https://ago.vermont.gov/categories/security-breach-notices"
VT_ORG_TYPE = {"Financial Services": "financial", "Health Care": "healthcare", "Not-For-Profit": "nonprofit", "Insurance": "financial",
               "Educational": "education", "Hospitality": "other", "Other Commercial": "other", "Government": "government"}


def parse_vt_list(html: str) -> list[dict]:
    """Columns: date reported, organization, organization type, VT residents affected, categories of data breached."""
    out = []
    for tds in _rows(html, 5):
        name, reported = tds[1].get_text(" ", strip=True), _iso(tds[0].get_text(" ", strip=True))
        c = _state_row(name, reported, _frag(VT_LIST, name, reported or ""), "VT", "Vermont AG security breach notice",
                       {"org_type_raw": tds[2].get_text(" ", strip=True).strip("\xa0 "), "persons_affected": tds[3].get_text(" ", strip=True),
                        "information_acquired": tds[4].get_text(" ", strip=True)})
        if c:
            out.append(c)
    return out


def vermont_ag(since: date, max_pages: int = 8) -> list[dict]:
    out: list[dict] = []
    for page in range(max_pages):  # four pages in October 2026; rows are not date-ordered across pages
        r = _get(VT_LIST, params={"page": page} if page else None, headers={"User-Agent": BROWSER_UA})
        rows = parse_vt_list(r.text) if r else []
        if not rows:
            break
        out += [c for c in rows if c["disclosed_date"] >= since.isoformat()]
        time.sleep(1)
    log.info("vermont_ag: %d candidates", len(out))
    return out


def washington_ag(since: date, max_pages: int = 40) -> list[dict]:
    out: list[dict] = []
    for page in range(max_pages):
        r = _get(WA_LIST, params={"page": page} if page else None, headers={"User-Agent": BROWSER_UA})
        rows = parse_wa_list(r.text) if r else []
        if not rows:
            break
        out += [c for c in rows if c["disclosed_date"] >= since.isoformat()]
        if rows[-1]["disclosed_date"] < since.isoformat():
            break
        time.sleep(1)
    log.info("washington_ag: %d candidates", len(out))
    return out


def _single_page(name: str, url: str, parse, since: date) -> list[dict]:
    r = _get(url, headers={"User-Agent": BROWSER_UA}, timeout=90)
    if not r:
        log.warning("%s: list unavailable (US-only site?)", name)
        return []
    out = [c for c in parse(r.text) if c["disclosed_date"] >= since.isoformat()]
    log.info("%s: %d candidates", name, len(out))
    return out


def oregon_doj(since: date) -> list[dict]:
    return _single_page("oregon_doj", OR_LIST, parse_or_list, since)


def south_carolina(since: date) -> list[dict]:
    return _single_page("south_carolina", SC_LIST, parse_sc_list, since)


# ---------------------------------------------------------------------------
# 3c. Have I Been Pwned breach list (free, no key, attribution asked). One row per
#     breach: name, domain, breach date, date added, count, data classes, a short
#     description that often says how. Spam lists, stealer logs and fabricated sets
#     are skipped; unverified breaches are kept but marked.
HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"
HIBP_DATA_CLASSES = {
    "credentials": ("password", "auth token", "security question", "pin", "private key", "session"),
    "financial": ("credit card", "bank", "payment", "purchase", "income", "credit status", "financial"),
    "medical": ("health", "medical", "prescription", "disabilit", "mental"),
    "personal": ("email", "name", "phone", "address", "date of birth", "gender", "ip address",
                 "social security", "government", "passport", "driver", "biometric", "age"),
}


def hibp_data_types(classes: list[str]) -> list[str]:
    out = set()
    for c in classes or []:
        cl = c.lower()
        hit = next((k for k, needles in HIBP_DATA_CLASSES.items() if any(n in cl for n in needles)), None)
        out.add(hit or "other")
    return sorted(out)


def hibp(since: date) -> list[dict]:
    r = _get(HIBP_URL, headers={"User-Agent": "breach-tracker (github.com/thesubtlety/breach-tracker)"})
    if not r:
        log.warning("hibp: unavailable")
        return []
    out = []
    for b in r.json():
        if b.get("IsFabricated") or b.get("IsSpamList") or b.get("IsStealerLog") or b.get("IsMalware"):
            continue
        added = (b.get("AddedDate") or "")[:10]
        if not added or date.fromisoformat(added) < since:
            continue
        desc = BeautifulSoup(b.get("Description") or "", "lxml").get_text(" ", strip=True)
        out.append({
            "org_name": b.get("Title") or b["Name"], "disclosed_date": added, "source_type": "hibp",
            "source_url": f"https://haveibeenpwned.com/Breach/{b['Name']}",
            "title": f"Have I Been Pwned: {b.get('Title') or b['Name']}", "text": desc or None,
            "structured_hint": {"breach_date": b.get("BreachDate"), "pwn_count": b.get("PwnCount"),
                                "data_classes": b.get("DataClasses") or [], "domain": b.get("Domain"),
                                "verified": bool(b.get("IsVerified")), "description": desc},
            "evidence_level_hint": "press_report", "org_country": "unknown",
        })
    log.info("hibp: %d candidates", len(out))
    return out


# 4. ransomware.live PRO API (free key from https://www.ransomware.live/my;
#    500k requests/month). The unauthenticated v2 API no longer exists.
#    Attribution required; non-commercial; do not re-serve their data as a feed.
#    We use it only to tag an incident as an actor claim and link to the permalink.
# ---------------------------------------------------------------------------
RWL_PRO = "https://api-pro.ransomware.live"


def rwl_get(path: str, **params) -> list[dict]:
    key = os.environ.get("RANSOMWARE_LIVE_API_KEY")
    if not key:
        return []
    r = _get(f"{RWL_PRO}{path}", headers={"X-API-KEY": key}, params=params or None)
    if not r:
        return []
    items = r.json()
    if isinstance(items, dict):
        items = items.get("victims") or items.get("data") or []
    return items


def rwl_candidate(v: dict) -> dict | None:
    name = v.get("victim") or v.get("post_title")
    disc = _iso((v.get("discovered") or v.get("attackdate") or "")[:10])
    if not (name and disc):
        return None
    country = (v.get("country") or "").strip().upper()
    return {
        "org_name": name,
        "disclosed_date": disc,
        "source_type": "ransomware_leak_site",
        "source_url": v.get("permalink") or f"https://www.ransomware.live/#{_slug(name)}",
        "title": f"Leak-site claim by {v.get('group')}",
        "text": (v.get("description") or "")[:2000] or None,
        "structured_hint": {
            "group": v.get("group"),
            "sector_raw": v.get("activity") or v.get("sector"),
            "country": country or None,
            "attack_date": v.get("attackdate"),
            "press": v.get("press"),
            "attribution": "Source: Ransomware.live",
        },
        "evidence_level_hint": "actor_claimed",
        "org_country": country if re.fullmatch(r"[A-Z]{2}", country) else "unknown",
    }


def ransomware_live(since: date) -> list[dict]:
    if not os.environ.get("RANSOMWARE_LIVE_API_KEY"):
        log.info("ransomware_live: RANSOMWARE_LIVE_API_KEY not set; skipped")
        return []
    out = [c for c in (rwl_candidate(v) for v in rwl_get("/victims/recent")) if c]
    out = [c for c in out if date.fromisoformat(c["disclosed_date"]) >= since]
    log.info("ransomware_live: %d candidates", len(out))
    return out


# ---------------------------------------------------------------------------
# 5. News RSS (discovery only; the article text is fetched for extraction but
#    we store only a supporting sentence plus the link)
# ---------------------------------------------------------------------------
RSS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed",
    "https://www.securityweek.com/feed/",
    "https://databreaches.net/feed/",
    "https://www.hackmageddon.com/feed/",
]
KEYWORDS = re.compile(
    r"\b(breach|breached|ransomware|hack|hacked|hackers|data (theft|stolen|leak)|"
    r"cyberattack|cyber attack|intrusion|compromise|unauthorized access|extortion)\b", re.I)


def rss(since: date) -> list[dict]:
    import feedparser

    out: list[dict] = []
    for feed in RSS_FEEDS:
        try:
            parsed = feedparser.parse(feed, agent=BROWSER_UA)
        except Exception as e:  # noqa: BLE001
            log.warning("rss %s failed: %s", feed, e)
            continue
        if getattr(parsed, "status", 200) >= 400 or (parsed.bozo and not parsed.entries):
            log.warning("rss %s: status=%s %s", feed, getattr(parsed, "status", None),
                        getattr(parsed, "bozo_exception", ""))
        for e in parsed.entries:
            title = e.get("title", "")
            if not KEYWORDS.search(title + " " + e.get("summary", "")):
                continue
            pub = e.get("published_parsed") or e.get("updated_parsed")
            d = date(*pub[:3]).isoformat() if pub else date.today().isoformat()
            if date.fromisoformat(d) < since:
                continue
            out.append({
                "org_name": "",  # LLM identifies the victim, or skips the item
                "disclosed_date": d,
                "source_type": "press",
                "source_url": e.get("link"),
                "title": title,
                "text": None,
                "structured_hint": {"feed": feed,
                                    "summary": BeautifulSoup(e.get("summary", ""), "lxml").get_text(" ", strip=True)[:1500] or None},
                "evidence_level_hint": "press_report",
                "org_country": "unknown",
            })
    log.info("rss: %d candidates", len(out))
    return out


# ---------------------------------------------------------------------------
# 6. Mastodon hashtag (public API, no auth). infosec.exchange now requires a
#    login for tag timelines; mastodon.social still serves them publicly.
# ---------------------------------------------------------------------------
MASTODON_TAG_URL = os.environ.get(
    "MASTODON_TAG_URL", "https://mastodon.social/api/v1/timelines/tag/databreach?limit=40")


def mastodon(since: date) -> list[dict]:
    out: list[dict] = []
    r = _get(MASTODON_TAG_URL)
    if not r:
        return out
    for st in r.json():
        d = (st.get("created_at") or "")[:10]
        if not d or date.fromisoformat(d) < since or (st.get("language") or "en") != "en":
            continue
        content = BeautifulSoup(st.get("content", ""), "lxml").get_text(" ", strip=True)
        card = st.get("card") or {}
        link = card.get("url") or st.get("url")
        if not KEYWORDS.search(content + " " + (card.get("title") or "")):
            continue
        out.append({
            "org_name": "",
            "disclosed_date": d,
            "source_type": "mastodon",
            "source_url": link,
            "title": card.get("title") or content[:120],
            "text": None if card.get("url") else content,
            "structured_hint": {"post": st.get("url")},
            "evidence_level_hint": "press_report",
            "org_country": "unknown",
        })
    log.info("mastodon: %d candidates", len(out))
    return out


ALL_SOURCES = {
    "sec_edgar": lambda since, until: sec_edgar(since, until),
    # HHS posts rows two to four weeks after their submission date; widen the window
    # and let the URL-keyed queue drop repeats.
    "hhs": lambda since, until: hhs(since - timedelta(days=45)),
    "maine_ag": lambda since, until: maine_ag(since),
    "california_ag": lambda since, until: california_ag(since),
    "texas_ag": lambda since, until: texas_ag(since),
    "washington_ag": lambda since, until: washington_ag(since),
    "vermont_ag": lambda since, until: vermont_ag(since),
    "oregon_doj": lambda since, until: oregon_doj(since),
    "south_carolina": lambda since, until: south_carolina(since),
    "hibp": lambda since, until: hibp(since),
    "ransomware_live": lambda since, until: ransomware_live(since),
    "rss": lambda since, until: rss(since),
    "mastodon": lambda since, until: mastodon(since),
}


def disabled_sources() -> set[str]:
    """Sources that cannot run in this environment; verify_sources skips them."""
    return {"ransomware_live"} if not os.environ.get("RANSOMWARE_LIVE_API_KEY") else set()


def collect(since_days: int, only: list[str] | None = None) -> list[dict]:
    until = date.today()
    since = until - timedelta(days=since_days)
    out: list[dict] = []
    for name, fn in ALL_SOURCES.items():
        if only and name not in only:
            continue
        try:
            out.extend(fn(since, until))
        except Exception as e:  # noqa: BLE001
            log.exception("source %s crashed: %s", name, e)
    return out
