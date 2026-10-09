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


def _norm(name: str | None) -> str:
    return re.sub(r"[^a-z0-9$]", "", (name or "").lower())


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
