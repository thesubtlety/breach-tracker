"""Actor enrichment. The model may only name a group the text attributes; what kind of
group it is and why they do it is public knowledge, so a small lookup fills variety
and motive deterministically instead of asking a model to guess. Names normalized to
lowercase alphanumerics. Extend the tables; never add a name you are unsure about."""
from __future__ import annotations

import re

ORGANIZED_CRIME = {
    # ransomware / extortion brands seen on leak sites and in press; all financially motivated
    "lockbit", "alphv", "blackcat", "clop", "cl0p", "qilin", "akira", "play", "blackbasta", "blacksuit",
    "royal", "ransomhub", "medusa", "hunters", "huntersinternational", "rhysida", "bianlian", "8base",
    "inc", "incransom", "lynx", "safepay", "dragonforce", "sinobi", "threeam", "3am", "everest", "cactus",
    "cuba", "vice", "vicesociety", "hive", "conti", "revil", "sodinokibi", "darkside", "blackbyte",
    "ragnarlocker", "ragnar", "snatch", "trigona", "nokoyawa", "abyss", "interlock", "fog", "embargo",
    "brain", "braincipher", "cicada3301", "kill", "killsec", "arcus", "arcusmedia", "sarcoma", "funksec",
    "lynxransomware", "anubis", "devman", "nightspire", "gunra", "silentransomgroup", "luna", "lunamoth",
    "scattered", "scatteredspider", "scatteredlapsushunters", "shinyhunters", "lapsus", "lapsus$",
    "unc3944", "0ktapus", "karakurt", "fin7", "fin11", "ta505", "evilcorp", "wizardspider", "trickbot",
    "emotet", "qakbot", "bumblebee", "ta577", "ta558", "storm0501", "storm0558", "muddledlibra",
}
STATE_AFFILIATED = {
    "apt1", "apt10", "apt28", "apt29", "apt31", "apt40", "apt41", "apt43", "fancybear", "cozybear",
    "sandworm", "voltvoltyphoon", "volttyphoon", "salttyphoon", "flaxtyphoon", "silktyphoon",
    "lazarus", "kimsuky", "andariel", "bluenoroff", "tradertraitor", "mustangpanda", "winnti",
    "hafnium", "unc3886", "unc2452", "nobelium", "midnightblizzard", "forestblizzard", "secretblizzard",
    "turla", "charmingkitten", "muddywater", "oilrig", "apt33", "apt34", "apt35", "mintsandstorm",
    "peachsandstorm", "cyberav3ngers", "gamaredon", "armageddon", "sednit", "earthestries", "redmenshen",
    "toddycat", "gallium", "unc5221", "unc5337", "unc4841", "unc5174", "redjuliett", "linentyphoon",
    "bronzebutler", "ta453", "ta416",
}
ACTIVIST = {"anonymous", "cyberpartisans", "belarusiancyberpartisans", "killnet", "noname057", "noname05716",
            "handala", "cyberav3ngers", "ghostsec", "siegedsec", "guacamaya"}
COUNTRY = {  # only where attribution is settled public record
    "apt28": "RU", "apt29": "RU", "sandworm": "RU", "fancybear": "RU", "cozybear": "RU", "turla": "RU", "gamaredon": "RU",
    "midnightblizzard": "RU", "forestblizzard": "RU", "secretblizzard": "RU", "nobelium": "RU", "unc2452": "RU",
    "apt41": "CN", "apt40": "CN", "apt31": "CN", "apt10": "CN", "apt1": "CN", "volttyphoon": "CN", "salttyphoon": "CN",
    "flaxtyphoon": "CN", "silktyphoon": "CN", "hafnium": "CN", "mustangpanda": "CN", "winnti": "CN", "unc3886": "CN",
    "linentyphoon": "CN", "redjuliett": "CN", "toddycat": "CN", "unc5221": "CN", "unc5174": "CN",
    "lazarus": "KP", "kimsuky": "KP", "andariel": "KP", "bluenoroff": "KP", "tradertraitor": "KP", "apt43": "KP",
    "charmingkitten": "IR", "muddywater": "IR", "oilrig": "IR", "apt33": "IR", "apt34": "IR", "apt35": "IR",
    "mintsandstorm": "IR", "peachsandstorm": "IR", "cyberav3ngers": "IR", "handala": "IR", "ta453": "IR",
    "cyberpartisans": "BY", "belarusiancyberpartisans": "BY",
}


ACTOR_ALIASES = {  # spellings that are one group
    "cl0p": "clop", "blackcat": "alphv", "sodinokibi": "revil", "lockbit3": "lockbit", "lockbit30": "lockbit",
    "3am": "threeam", "inc": "incransom", "hunters": "huntersinternational", "lynxransomware": "lynx",
    "darkoverlord": "thedarkoverlord", "ragnar": "ragnarlocker", "vice": "vicesociety", "kill": "killsec",
    "scattered": "scatteredspider", "unc3944": "scatteredspider", "muddledlibra": "scatteredspider",
}


def _norm(name: str | None) -> str:
    return re.sub(r"[^a-z0-9$]", "", re.sub(r"\(.*?\)", "", name or "").lower())


def actor_key(name: str | None) -> str:
    """Group id: lowercase alphanumerics, aliases folded. Empty when there is no name."""
    k = _norm(name)
    return ACTOR_ALIASES.get(k, k)


_CLAIM_TITLE = re.compile(r"leak-site claim by (.+)$", re.I)


def claim_groups(r: dict) -> list[str]:
    """Groups whose leak-site claims are attached to a record, in source order."""
    out = []
    for s in r.get("sources") or []:
        if s.get("type") == "ransomware_leak_site":
            m = s.get("title") and _CLAIM_TITLE.search(s["title"])
            k = actor_key(m.group(1) if m else (r.get("actor") or {}).get("name"))
            if k and k not in out:
                out.append(k)
    return out


def claim_group(r: dict) -> str:
    return (claim_groups(r) or [""])[0]


def record_groups(r: dict) -> set[str]:
    return {k for k in [actor_key((r.get("actor") or {}).get("name")), *claim_groups(r)] if k}


def actor_registry(rows: list[dict], claim_stats: dict[str, dict] | None = None) -> list[dict]:
    """One entry per group: records naming it or carrying its claim, plus the claim figures."""
    from collections import Counter, defaultdict
    by_key: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        for k in record_groups(r):
            by_key[k].append(r)
    claim_stats = claim_stats or {}
    out = []
    for k in set(by_key) | set(claim_stats):
        recs = by_key.get(k, [])
        names = Counter(r["actor"]["name"].strip() for r in recs if actor_key((r.get("actor") or {}).get("name")) == k)
        name = max(names, key=lambda n: (names[n], -len(n))) if names else k
        dates = sorted(r["disclosed_date"] for r in recs)
        a = enrich_actor({"name": name}) if recs else enrich_actor({"name": k})
        known = [r for r in recs if r.get("initial_access") not in (None, "unknown")]
        vendors = Counter(v["name"] for r in recs for v in (r.get("derived") or {}).get("vendors") or [])
        out.append({
            "id": k, "name": name, "aliases": sorted(n for n in names if n != name),
            "variety": a["variety"], "motive": a["motive"], "country": a.get("country"),
            "incidents": len(recs), "first": dates[0] if dates else None, "last": dates[-1] if dates else None,
            "named": sum(1 for r in recs if actor_key((r.get("actor") or {}).get("name")) == k),
            "claimed": sum(1 for r in recs if k in claim_groups(r)),
            "ransomware": sum(1 for r in recs if r.get("ransomware") is True),
            "sectors": Counter(r["org_type"] for r in recs if r.get("org_type") not in (None, "unknown")).most_common(5),
            "countries": Counter(r.get("org_country") for r in recs if r.get("org_country") not in (None, "unknown")).most_common(5),
            "initial_access": Counter(r["initial_access"] for r in known).most_common(),
            "vendors": vendors.most_common(5),
            "claims": claim_stats.get(k),
        })
    out.sort(key=lambda o: (-(o["incidents"] + ((o["claims"] or {}).get("claims") or 0) - ((o["claims"] or {}).get("confirmed") or 0)), o["name"]))
    return out


def default_actor() -> dict:
    return {"category": "unknown", "variety": "unknown", "motive": "unknown", "name": None, "country": None}


def enrich_actor(actor: dict | None) -> dict:
    """Fill category/variety/motive/country from the name when the name is a known group.
    Never overrides a value the source stated (anything other than unknown/null)."""
    a = dict(default_actor(), **(actor or {}))
    key = _norm(a.get("name"))
    if not key:
        return a
    if key in STATE_AFFILIATED:
        guess = ("external", "state_affiliated", "espionage")
    elif key in ACTIVIST:
        guess = ("external", "activist", "ideology")
    elif key in ORGANIZED_CRIME or key.endswith("ransomware") or key.endswith("ransom"):
        guess = ("external", "organized_crime", "financial")
    else:
        return a
    for field, val in zip(("category", "variety", "motive"), guess):
        if a.get(field) in (None, "unknown"):
            a[field] = val
    if not a.get("country") and key in COUNTRY:
        a["country"] = COUNTRY[key]
    return a


def default_third_party() -> dict:
    return {"involved": None, "archetype": None, "vendor": None}
