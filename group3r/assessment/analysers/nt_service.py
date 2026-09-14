"""Analyser for NT Service settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import NtServiceSetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..trustee_match import match_trustee

# Trustees to skip (high-priv, expected to have service perms)
_SKIP_TRUSTEES = {
    "administrators", "administrator", "local system", "system",
    "nt authority\\system",
}


class NtServiceAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: NtServiceSetting = self.setting

        # Check for cpassword
        if setting.cpassword:
            password = setting.decrypt_cpassword(setting.cpassword)
            self.add_finding(GpoFinding(
                finding_reason=f"Group Policy Preferences password found:{password or setting.cpassword}",
                finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                triage=Triage.BLACK,
            ))

        # Analyse service SDDL if present
        if setting.sddl:
            from ...sddl.parser import SddlDescriptor
            from ...sddl.constants import SecurableObjectType
            from ..sddl_analyser import analyse_sddl

            try:
                sddl = SddlDescriptor(setting.sddl, SecurableObjectType.WINDOWS_SERVICE)
                aces = analyse_sddl(sddl)

                write_rights = {
                    "WRITE_DAC", "WRITE_OWNER", "SERVICE_CHANGE_CONFIG",
                    "GENERIC_ALL", "GENERIC_WRITE", "ALL_ACCESS",
                }

                for ace in aces:
                    if ace.ace_type != "Allow":
                        continue

                    # Skip high-priv trustees
                    if ace.trustee.lower() in _SKIP_TRUSTEES:
                        continue

                    interesting = [r for r in ace.rights if r in write_rights]
                    if not interesting:
                        continue

                    to = match_trustee(options, ace.trustee, ace.trustee_sid)
                    if not to or to.get("high_priv"):
                        continue
                    if to.get("low_priv") or to.get("target"):
                        svc_name = setting.service_name or setting.name or ""
                        self.add_finding(GpoFinding(
                            finding_reason="A Windows service's ACL is being configured to grant abusable permissions to a target trustee.",
                            finding_detail=(
                                f"This should allow local privilege escalation "
                                f"on affected hosts. Service: {svc_name}, "
                                f"Trustee: {to.get('display_name') or ace.trustee}"
                            ),
                            triage=Triage.RED,
                            acl_result=[ace],
                        ))
            except Exception:
                pass

        return self.result
