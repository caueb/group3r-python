"""Analyser for Shortcut settings."""

from __future__ import annotations

import re

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import ShortcutSetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..path_analyser import analyse_setting_path
from ..path_utils import is_unc

_PASSWORD_PATTERN = re.compile(
    r"(pass|pw|cred|secret|key|token|\-p\s|/p\s)", re.IGNORECASE
)


class ShortcutAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: ShortcutSetting = self.setting

        if setting.target_path and is_unc(setting.target_path):
            pr = analyse_setting_path(options, setting.target_path)
            if pr.file_writable or pr.directory_writable or pr.parent_directory_writable:
                self.add_finding(GpoFinding(
                    finding_reason="Shortcut points at a file that you can modify.",
                    finding_detail=f"It points to {setting.target_path}, so maybe see what happens if you modify that file.",
                    triage=Triage.RED,
                    path_findings=[pr],
                ))
            else:
                self.add_finding(GpoFinding(
                    finding_reason="Shortcut points at a network path. If that file is writable, you can modify what it launches.",
                    finding_detail=f"It points to {setting.target_path}. Writability was not verified.",
                    triage=Triage.RED,
                    path_findings=[pr],
                ))

        if setting.start_in and is_unc(setting.start_in):
            pr = analyse_setting_path(options, setting.start_in)
            if pr.directory_writable or pr.parent_directory_writable:
                self.add_finding(GpoFinding(
                    finding_reason="Shortcut is configured to use a working directory that you can write to.",
                    finding_detail=f"You might be able to pull some DLL sideloading shenanigans in {setting.start_in}",
                    triage=Triage.YELLOW,
                    path_findings=[pr],
                ))
            else:
                self.add_finding(GpoFinding(
                    finding_reason="Shortcut is configured to use a working directory on a network path.",
                    finding_detail=f"You might be able to pull some DLL sideloading shenanigans in {setting.start_in} if it is writable. Writability was not verified.",
                    triage=Triage.YELLOW,
                    path_findings=[pr],
                ))

        if setting.arguments and _PASSWORD_PATTERN.search(setting.arguments):
            self.add_finding(GpoFinding(
                finding_reason="Shortcut has an arguments setting that looks like it might have a password in it?",
                finding_detail=f"Arguments were: {setting.arguments}",
                triage=Triage.YELLOW,
            ))

        return self.result
