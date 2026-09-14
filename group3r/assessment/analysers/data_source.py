"""Analyser for DataSource settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import DataSourceSetting
from ...options import AssessmentOptions
from ..analyser import Analyser


class DataSourceAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting = self.setting

        cpassword = getattr(setting, "cpassword", "")

        if cpassword:
            decrypted = setting.decrypt_cpassword(cpassword)
            self.add_finding(GpoFinding(
                finding_reason=f"Group Policy Preferences password found:{decrypted or cpassword}",
                finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                triage=Triage.BLACK,
            ))

        # For data sources, also flag connection info
        if isinstance(setting, DataSourceSetting):
            if setting.dsn or setting.driver:
                self.add_finding(GpoFinding(
                    finding_reason="Potentially useful database connection info identified.",
                    finding_detail="Could be helpful for targeting other attacks.",
                    triage=Triage.GREEN,
                ))

        return self.result
