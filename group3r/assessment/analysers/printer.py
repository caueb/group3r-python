"""Analyser for Printer, Drive, and User settings (GPP cpassword checks)."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...options import AssessmentOptions
from ..analyser import Analyser


class PrinterAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting = self.setting

        cpassword = getattr(setting, "cpassword", "")
        password = getattr(setting, "password", "")

        if cpassword:
            decrypted = setting.decrypt_cpassword(cpassword)
            self.add_finding(GpoFinding(
                finding_reason=f"Group Policy Preferences password found:{decrypted or cpassword}",
                finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                triage=Triage.BLACK,
            ))
        elif password:
            self.add_finding(GpoFinding(
                finding_reason=f"Group Policy Preferences password found:{password}",
                finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                triage=Triage.BLACK,
            ))

        return self.result
