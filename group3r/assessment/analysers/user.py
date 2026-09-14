"""Analyser for local User GPP settings (cpassword)."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import UserSetting
from ...options import AssessmentOptions
from ..analyser import Analyser


class UserAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: UserSetting = self.setting

        if setting.cpassword:
            decrypted = setting.decrypt_cpassword(setting.cpassword)
            self.add_finding(GpoFinding(
                finding_reason=f"Group Policy Preferences password found:{decrypted or setting.cpassword}",
                finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                triage=Triage.BLACK,
            ))

        return self.result
