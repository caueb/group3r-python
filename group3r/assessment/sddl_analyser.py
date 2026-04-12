"""SDDL Analyser - converts parsed SDDL into simplified ACE results."""

from __future__ import annotations

from ..models.findings import SimpleAce
from ..models.trustees import Trustee
from ..sddl.parser import SddlDescriptor


def analyse_sddl(sddl: SddlDescriptor) -> list[SimpleAce]:
    """Convert a parsed SDDL descriptor into a list of SimpleAce objects."""
    result: list[SimpleAce] = []

    if sddl.owner and sddl.owner.alias:
        result.append(SimpleAce(
            ace_type="Allow",
            rights=["Owner"],
            trustee=sddl.owner.alias,
        ))

    if sddl.dacl and sddl.dacl.aces:
        for ace in sddl.dacl.aces:
            ace_type = "Allow"
            if ace.ace_type == "OBJECT_ACCESS_DENIED" or ace.ace_type == "ACCESS_DENIED":
                ace_type = "Deny"

            sid_display = ""
            sid_raw = ""
            if ace.ace_sid:
                sid_display = ace.ace_sid.alias
                sid_raw = ace.ace_sid.raw

            simple_ace = SimpleAce(
                ace_type=ace_type,
                rights=list(ace.rights) if ace.rights else [],
                trustee=sid_display or sid_raw,
            )
            result.append(simple_ace)

    return result
