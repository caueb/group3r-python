"""Analyser for Package (MSI) deployment settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import PackageSetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..path_analyser import analyse_setting_path
from ..path_utils import is_unc


class PackageAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: PackageSetting = self.setting

        for msi_path in setting.msi_file_list:
            if not msi_path or not is_unc(msi_path):
                continue
            pr = analyse_setting_path(options, msi_path)
            if pr.file_writable or pr.directory_writable or pr.parent_directory_writable:
                self.add_finding(GpoFinding(
                    finding_reason="MSI package installer setting points at a file that you can modify.",
                    finding_detail=f"It points to {msi_path} so maybe see what happens if you replace that file with something fun.",
                    triage=Triage.RED,
                    path_findings=[pr],
                ))
            else:
                self.add_finding(GpoFinding(
                    finding_reason="MSI package installer setting points at a network path.",
                    finding_detail=f"It points to {msi_path}. If that file is writable, replace it with something fun. Writability was not verified.",
                    triage=Triage.RED,
                    path_findings=[pr],
                ))

        return self.result
