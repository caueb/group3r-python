"""Analyser for Network Share settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import NetworkShareSetting
from ...options import AssessmentOptions
from ..analyser import Analyser


class NetworkShareAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: NetworkShareSetting = self.setting

        if setting.name and setting.path:
            self.add_finding(GpoFinding(
                finding_reason=(
                    f"Network share '{setting.name}' configured at "
                    f"path '{setting.path}'."
                ),
                finding_detail=(
                    f"Comment: {setting.comment or 'None'}, "
                    f"ABE: {setting.abe or 'Not set'}"
                ),
                triage=Triage.GREEN,
            ))

        return self.result
