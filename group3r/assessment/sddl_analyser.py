"""SDDL Analyser - converts parsed SDDL into simplified ACE results."""

from __future__ import annotations

from ..models.enums import Triage
from ..models.findings import GpoFinding, SimpleAce
from ..sddl.parser import SddlDescriptor

# GPO object rights that let a trustee change policy (better than C#, which
# Black-flagged every GPO that had any ACE at all).
_GPO_WRITE_RIGHTS = {
    "GENERIC_ALL", "GENERIC_WRITE", "WRITE_DAC", "WRITE_OWNER",
    "CREATE_CHILD", "WRITE_PROPERTY", "ALL_ACCESS", "STANDARD_RIGHTS_ALL",
    "Owner",
}


def analyse_sddl(sddl: SddlDescriptor) -> list[SimpleAce]:
    """Convert a parsed SDDL descriptor into a list of SimpleAce objects."""
    result: list[SimpleAce] = []

    if sddl.owner and sddl.owner.alias:
        result.append(SimpleAce(
            ace_type="Allow",
            rights=["Owner"],
            trustee=sddl.owner.alias,
            trustee_sid=sddl.owner.raw or "",
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
                trustee_sid=sid_raw,
            )
            result.append(simple_ace)

    return result


def analyse_gpo_acl(sddl_string: str, options) -> list[GpoFinding]:
    """Flag GPO nTSecurityDescriptor ACLs that grant write to low-priv trustees."""
    if not sddl_string:
        return []

    from ..sddl.constants import SecurableObjectType
    from .trustee_match import match_trustee

    try:
        parsed = SddlDescriptor(sddl_string, SecurableObjectType.DIRECTORY)
        aces = analyse_sddl(parsed)
    except Exception:
        return []

    findings: list[GpoFinding] = []
    seen = set()
    for ace in aces:
        if ace.ace_type != "Allow":
            continue
        interesting = [r for r in ace.rights if r in _GPO_WRITE_RIGHTS]
        if not interesting:
            continue
        to = match_trustee(options, ace.trustee, ace.trustee_sid)
        if not to or to.get("high_priv"):
            continue
        if not (to.get("low_priv") or to.get("target")):
            continue
        key = (to.get("display_name") or ace.trustee, tuple(interesting))
        if key in seen:
            continue
        seen.add(key)
        name = to.get("display_name") or ace.trustee
        findings.append(GpoFinding(
            finding_reason="Found some interesting ACLs on this GPO. Might wanna check 'em out.",
            finding_detail=(
                f"{name} was granted {', '.join(interesting)} on this GPO. "
                "WriteDACL / GenericAll / CreateChild on a GPO is a common privesc path."
            ),
            triage=Triage.BLACK,
            acl_result=[ace],
        ))
    return findings
