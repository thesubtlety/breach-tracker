#!/usr/bin/env python3
"""Fetch Maine AG data-breach notices from a US address and save the raw pages.
Standard library only: copy this one file anywhere with Python 3.9+ and run it.

    python3 fetch_maine.py                      # -> maine_raw.zip in the current directory
    python3 fetch_maine.py --max-pages 5000 --out maine_raw.zip

maine.gov serves the notice list only to US IP addresses. This script does nothing
clever: it downloads the list, every notice page it links to, and any further index
pages it finds, and zips them. Parsing happens later with
`pipeline/backfill.py --maine-zip maine_raw.zip`, so selector problems are fixed
without re-fetching. Polite by design: one request every half second.
"""
import argparse
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

DIR = "https://www.maine.gov/agviewer/content/ag/985235c7-cb95-4be2-8792-a1252b4f8318/"
START = [DIR + "list.html", DIR + "index.shtml"]
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/130.0 Safari/537.36")
NOTICE = re.compile(r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.s?html$", re.I)


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,*/*;q=0.8",
                                               "Accept-Language": "en-US,en;q=0.9"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            final = r.geturl()
            return r.status, final, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, ""
    except Exception as e:  # noqa: BLE001
        print(f"  ! {url}: {e}", file=sys.stderr)
        return 0, url, ""


def links(html, base):
    out = []
    for href in re.findall(r'href=["\']([^"\']+)["\']', html, re.I):
        u = urllib.parse.urljoin(base, href.split("#")[0])
        if u.startswith(DIR):
            out.append(u)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="maine_raw.zip")
    ap.add_argument("--max-pages", type=int, default=4000)
    ap.add_argument("--sleep", type=float, default=0.5)
    args = ap.parse_args()

    queue, seen, saved, blocked = list(START), set(), 0, 0
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as z:
        while queue and saved < args.max_pages:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            status, final, html = get(url)
            time.sleep(args.sleep)
            if status != 200 or not final.startswith(DIR):
                blocked += 1
                print(f"  {status} {url} -> {final}", file=sys.stderr)
                if url in START and blocked == len(START):
                    print("Both index URLs are unavailable. Is this a US address? "
                          "(403 or a redirect to a generic AG page means no.)", file=sys.stderr)
                continue
            name = url[len(DIR):] or "index.html"
            z.writestr(name, html)
            saved += 1
            is_notice = bool(NOTICE.search(url))
            if not is_notice:  # index-like page: follow everything in the directory
                for u in links(html, url):
                    if u not in seen:
                        queue.append(u)
            if saved % 50 == 0:
                print(f"  saved {saved}, queued {len(queue)}", file=sys.stderr)
    if saved:
        print(f"saved {saved} pages to {args.out} ({blocked} unavailable). Send the zip back.")
    else:
        print("nothing saved; see messages above.")
    return 0 if saved else 1


if __name__ == "__main__":
    sys.exit(main())
