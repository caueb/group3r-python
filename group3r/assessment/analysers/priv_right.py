"""Analyser for Privilege Rights settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import PrivRightSetting
from ...options import AssessmentOptions
from ..analyser import Analyser

# Service accounts that canonically have SeAssignPrimaryTokenPrivilege and
# SeImpersonatePrivilege - skip these to avoid noise (matches C# logic).
_SERVICE_ACCOUNT_SIDS = {
    "S-1-5-19",  # NT AUTHORITY\LOCAL SERVICE
    "S-1-5-20",  # NT AUTHORITY\NETWORK SERVICE
}
_SERVICE_ACCOUNT_NAMES = {
    "nt authority\\local service",
    "nt authority\\network service",
    "local service",
    "network service",
}
_SERVICE_PRIVS = {
    "SeAssignPrimaryTokenPrivilege",
    "SeImpersonatePrivilege",
}


class PrivRightAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: PrivRightSetting = self.setting

        # Find the privilege in assessment options
        priv_option = None
        for pr in options.priv_rights:
            if pr.get("privilege") == setting.privilege:
                priv_option = pr
                break

        if priv_option is None:
            return self.result

        is_remote = priv_option.get("grants_remote_access", False)
        is_local_privesc = priv_option.get("local_privesc", False)

        if not is_remote and not is_local_privesc:
            return self.result

        # Check each trustee assigned this privilege
        for trustee in setting.trustees:
            trustee_sid = trustee.sid
            trustee_name = trustee.display_name or trustee.sid

            # Match against assessment trustee options
            for to in options.trustee_options:
                matched = False

                if to.get("display_name", "").lower() == trustee_name.lower():
                    matched = True
                elif trustee_sid and to.get("sid", "").lower() == trustee_sid.lower():
                    matched = True
                elif trustee_sid and to.get("domain_sid", False) and "-" in trustee_sid:
                    try:
                        ace_rid = trustee_sid.rsplit("-", 1)[1]
                        trustee_rid = to["sid"].rsplit("-", 1)[1]
                        if ace_rid == trustee_rid:
                            matched = True
                    except (IndexError, KeyError):
                        pass

                if not matched:
                    continue

                # C# checks high_priv first (expected, skip)
                if to.get("high_priv", False):
                    break

                detail = (f"{setting.privilege} was assigned to "
                          f"{trustee_name} - {trustee_sid}")

                if to.get("low_priv", False):
                    # Skip service accounts for service-specific privileges
                    if setting.privilege in _SERVICE_PRIVS:
                        if (trustee_sid in _SERVICE_ACCOUNT_SIDS or
                                trustee_name.lower() in _SERVICE_ACCOUNT_NAMES):
                            break

                    self.add_finding(GpoFinding(
                        finding_reason="Well-known low-priv user/group assigned an interesting OS privilege.",
                        finding_detail=detail,
                        triage=Triage.BLACK,
                    ))
                    break
                elif to.get("target", False):
                    self.add_finding(GpoFinding(
                        finding_reason="Targeted user/group assigned an interesting OS privilege.",
                        finding_detail=detail,
                        triage=Triage.RED,
                    ))
                else:
                    self.add_finding(GpoFinding(
                        finding_reason="User/group assigned an interesting OS privilege. ",
                        finding_detail=detail,
                        triage=Triage.GREEN,
                    ))
                    break

        return self.result
