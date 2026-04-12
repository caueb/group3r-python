"""Analyser for Shortcut settings."""

from __future__ import annotations

import re

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import ShortcutSetting
from ...options import AssessmentOptions
from ..analyser import Analyser

_PASSWORD_PATTERN = re.compile(
    r"(pass|pw|cred|secret|key|token|\-p\s|/p\s)", re.IGNORECASE
)


class ShortcutAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: ShortcutSetting = self.setting

        # Check target path - RED
        if setting.target_path:
            self.add_finding(GpoFinding(
                finding_reason="Shortcut points at a file that you can modify.",
                finding_detail=f"It points to {setting.target_path}, so maybe see what happens if you modify that file.",
                triage=Triage.RED,
            ))

        # Check working directory - YELLOW (DLL sideloading)
        if setting.start_in:
            self.add_finding(GpoFinding(
                finding_reason="Shortcut is configured to use a working directory that you can write to.",
                finding_detail=f"You might be able to pull some DLL sideloading shenanigans in {setting.start_in}",
                triage=Triage.YELLOW,
            ))

        # Check arguments for credentials - YELLOW
        if setting.arguments and _PASSWORD_PATTERN.search(setting.arguments):
            self.add_finding(GpoFinding(
                finding_reason="Shortcut has an arguments setting that looks like it might have a password in it?",
                finding_detail=f"Arguments were: {setting.arguments}",
                triage=Triage.YELLOW,
            ))

        return self.result
