"""Match GPO trustees against AssessmentOptions.trustee_options."""

from __future__ import annotations

from typing import Optional


def match_trustee(options, name: str = "", sid: str = "") -> Optional[dict]:
    """Return the first matching trustee option, or None."""
    name_l = (name or "").lower()
    sid_l = (sid or "").lower()
    name_short = name_l.rsplit("\\", 1)[-1] if name_l else ""

    for to in options.trustee_options:
        to_name = (to.get("display_name") or "").lower()
        to_sid = (to.get("sid") or "").lower()
        to_short = to_name.rsplit("\\", 1)[-1] if to_name else ""

        if name_l and to_name and name_l == to_name:
            return to
        if name_short and to_short and name_short == to_short and name_short not in {
            "", "users", "guests", "service",
        }:
            # Allow BUILTIN\\Administrators vs Administrators, but not
            # the ambiguous short names Users/Guests/Service.
            if "\\" in name_l or "\\" in to_name:
                return to
        if sid_l and to_sid:
            if sid_l == to_sid:
                return to
            if to.get("domain_sid") and "-" in sid_l and "-" in to_sid:
                if sid_l.rsplit("-", 1)[-1] == to_sid.rsplit("-", 1)[-1]:
                    return to
    return None


def is_high_priv(options, name: str = "", sid: str = "") -> bool:
    matched = match_trustee(options, name, sid)
    return bool(matched and matched.get("high_priv"))


def is_low_priv(options, name: str = "", sid: str = "") -> bool:
    matched = match_trustee(options, name, sid)
    return bool(matched and matched.get("low_priv"))


def is_target(options, name: str = "", sid: str = "") -> bool:
    matched = match_trustee(options, name, sid)
    return bool(matched and matched.get("target"))
