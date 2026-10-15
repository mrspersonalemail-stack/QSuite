"""One mention policy for both security engine and independent watchdog."""

import re


def notification(level: int, owner: str | None):
    if type(level) is not int or not 0 <= level <= 5:
        raise ValueError("invalid notification level")
    if owner and not re.fullmatch(r"[0-9]{15,22}", owner):
        raise ValueError("mention target must be a Discord user ID")
    if level == 0:
        return {"send": False, "content": "", "allowed_mentions": {"parse": []}}
    if level == 2 and owner:
        return {"send": True, "content": f"<@{owner}>", "allowed_mentions": {"parse": [], "users": [owner]}}
    if level >= 3:
        return {"send": True, "content": "@everyone", "allowed_mentions": {"parse": ["everyone"]}}
    return {"send": True, "content": "", "allowed_mentions": {"parse": []}}
