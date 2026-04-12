"""Analyser for Package (MSI) deployment settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import PackageSetting
from ...options import AssessmentOptions
from ..analyser import Analyser


class PackageAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: PackageSetting = self.setting

        for msi_path in setting.msi_file_list:
            if not msi_path:
                continue
            self.add_finding(GpoFinding(
                finding_reason="MSI package installer setting points at a file that you can modify.",
                finding_detail=f"It points to {msi_path}, so maybe see what happens if you replace that file with something fun.",
                triage=Triage.RED,
            ))

        return self.result
