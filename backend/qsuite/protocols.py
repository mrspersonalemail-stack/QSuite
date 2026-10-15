"""Named protocols and evidence-based correlation; geography never proves hostility."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress

from .config import SecurityPolicy
from .notifications import notification as notification


@dataclass(frozen=True)
class Protocol:
    name: str
    description: str
    level: int
    response: str


PROTOCOLS = {
    p.name: p
    for p in [
        Protocol("HOMEGUARD", "Trusted LAN activity; audit without geography enforcement.", 0, "audit"),
        Protocol("CARPATHIAN", "Successful authentication from a configured trusted country.", 0, "audit"),
        Protocol("FOREIGN", "Unusual foreign authentication with low confidence.", 1, "observe"),
        Protocol(
            "EUROPA",
            "Authentication outside trusted countries but within configured continent.",
            1,
            "observe",
        ),
        Protocol("EXILE", "Successful authentication outside trusted geographic region.", 2, "investigate"),
        Protocol("SIEGE", "Correlated authentication failures or password spray.", 2, "investigate"),
        Protocol("TRANSFERWATCH", "Sensitive transfer signal requiring targeted inspection.", 2, "inspect"),
        Protocol("SENTINEL", "Scheduled or targeted malware scan.", 0, "scan"),
        Protocol("PLAGUE", "Confirmed scanner detection; preserve source for quarantine review.", 3, "quarantine"),
        Protocol(
            "OUTBREAK",
            "Multiple confirmed malware detections or critical compromise indicators.",
            4,
            "investigate",
        ),
        Protocol("BLINDSPOT", "Monitoring or scanner/signature coverage is degraded.", 1, "investigate"),
        Protocol(
            "RAVEN", "Unexpected persistence definition change; legitimacy unconfirmed.", 2, "investigate"
        ),
        Protocol(
            "GHOST", "Unexpected identity or authorized-key change; legitimacy unconfirmed.", 2, "investigate"
        ),
        Protocol("ANCHOR", "SSH/PAM/sudo policy changed outside an approved baseline.", 2, "investigate"),
        Protocol("THRONE", "Management component changed outside an approved baseline.", 2, "investigate"),
        Protocol("FORGE", "Protected file differs from approved baseline.", 2, "investigate"),
        Protocol(
            "CROWN", "Strong evidence of unauthorized privilege escalation.", 3, "contain if attributable"
        ),
        Protocol(
            "SABRE", "Strong evidence of unauthorized destructive behavior.", 4, "contain if attributable"
        ),
        Protocol("BLACKOUT", "Confirmed security evidence destruction or tampering.", 4, "investigate"),
        Protocol(
            "CERBERUS", "Independent observer reports unexpected security engine failure.", 4, "investigate"
        ),
        Protocol(
            "LOCKDOWN",
            "Operator-declared emergency containment request.",
            5,
            "require recovery-safe enforcement",
        ),
        Protocol("ALLCLEAR", "Previously active condition has been resolved.", 0, "audit recovery"),
    ]
}
LEVELS = ["NORMAL", "NOTICE", "SUSPICIOUS", "HOSTILE", "CRITICAL", "LOCKDOWN"]


def classify_login(source: str | None, country: str | None, continent: str | None, policy: SecurityPolicy):
    if source:
        address = ipaddress.ip_address(source)
        if any(address in ipaddress.ip_network(network) for network in policy.trusted_cidrs):
            return PROTOCOLS["HOMEGUARD"]
    if country and country in policy.trusted_countries:
        return PROTOCOLS["CARPATHIAN"]
    if not country or not continent:
        # Unknown lookup is explicitly recorded, not guessed as a foreign country.
        return Protocol("FOREIGN", "Successful authentication; geography UNKNOWN.", 1, "observe")
    if continent in policy.trusted_continents:
        return PROTOCOLS["EUROPA"]
    return PROTOCOLS["EXILE"]


def correlate(events: list[dict], weights: dict[str, int] | None = None):
    """A level and a separate eligibility decision; severity alone never identifies an attacker."""
    level = max((PROTOCOLS[e["protocol"]].level for e in events), default=0)
    score = min(100, sum((weights or {}).get(name, 0) for name in {e["protocol"] for e in events}))
    strong = {e["protocol"] for e in events} & {"GHOST", "ANCHOR", "RAVEN", "FORGE", "THRONE"}
    if len(strong) >= 2 and any(e.get("attributed") and e.get("session") for e in events):
        level = max(level, 3)
    eligible = [
        e
        for e in events
        if e.get("attributed") and e.get("session") and e.get("source") and e.get("confirmed_hostile")
    ]
    # A changed config, arbitrary scan detection, geography or failed sudo is not confirmed hostility.
    sources = {e["source"] for e in eligible}
    return {
        "level": min(level, 5),
        "score": score,
        "containment_eligible": level >= 3 and len(sources) == 1,
        "source": next(iter(sources)) if level >= 3 and len(sources) == 1 else None,
        "reason": "confirmed attributed hostile evidence" if eligible else "attribution/hostility not proven",
    }
