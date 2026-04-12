"""Analyser for Kerberos Policy settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import KerbPolicySetting
from ...options import AssessmentOptions
from ..analyser import Analyser

# Matches C# KerbPolicyAnalyser exactly
_SETTINGS: dict[str, dict] = {
    "MaxTicketAge": {
        "default": "10",
        "reason_fmt": "Non-default maximum Kerberos ticket age configured. {value}",
        "detail": "Dunno, bit interesting.",
    },
    "MaxRenewAge": {
        "default": "7",
        "reason_fmt": "Non-default maximum Kerberos renewal period configured. {value}",
        "detail": "Dunno, bit interesting.",
    },
    "MaxServiceAge": {
        "default": "600",
        "reason_fmt": "Non-default maximum Kerberos service ticket age configured. {value}",
        "detail": "Dunno, bit interesting.",
    },
    "MaxClockSkew": {
        "default": "5",
        "reason_fmt": "Non-default maximum Kerberos clock skew setting. {value}",
        "detail": "Dunno, bit interesting.",
    },
    "TicketValidateClient": {
        "default": "1",
        "reason_fmt": "Kerberos 'Enforce user logon restrictions' setting is disabled.",
        "detail": "Probably no significant impact, read here for more details: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-user-logon-restrictions",
    },
}


class KerbPolicyAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: KerbPolicySetting = self.setting

        config = _SETTINGS.get(setting.key)
        if config and setting.value != config["default"]:
            self.add_finding(GpoFinding(
                finding_reason=config["reason_fmt"].format(value=setting.value),
                finding_detail=config["detail"],
                triage=Triage.GREEN,
            ))

        return self.result
