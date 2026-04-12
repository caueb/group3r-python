"""Analyser for Script settings."""

from __future__ import annotations

import re

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import ScriptSetting
from ...options import AssessmentOptions
from ..analyser import Analyser

_PASSWORD_PATTERN = re.compile(
    r"(pass|pw|cred|secret|key|token|\-p\s|/p\s)", re.IGNORECASE
)


class ScriptAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: ScriptSetting = self.setting
        script_type = setting.script_type.value if setting.script_type else "Script"

        # Check for password-like content in parameters - YELLOW
        if setting.parameters and _PASSWORD_PATTERN.search(setting.parameters):
            self.add_finding(GpoFinding(
                finding_reason=f"{script_type} script has an arguments setting that looks like it might have a password in it?",
                finding_detail=f"Arguments were: {setting.parameters}",
                triage=Triage.YELLOW,
            ))

        # Analyse the script path
        if setting.cmd_line:
            cmd_line = setting.cmd_line.strip()

            if cmd_line.startswith("\\\\"):
                # Network path - BLACK (writable script = code execution)
                self.add_finding(GpoFinding(
                    finding_reason=f"Writable {script_type} script file identified at {cmd_line}",
                    finding_detail=(
                        "This script will run in the context of the users/computers "
                        "to which this GPO is applied. Change the script, get command "
                        "exec as those users/computers."
                    ),
                    triage=Triage.BLACK,
                ))
            elif cmd_line:
                # Local/relative path - RED (missing script with writable parent)
                self.add_finding(GpoFinding(
                    finding_reason=f"Missing {script_type} script with a writable parent dir. The original target path was {cmd_line}",
                    finding_detail=(
                        "Recreate the missing parts of the path in the parent dir, "
                        "put your code in the script. It will then run in the context "
                        "of the users/computers to which this GPO is applied."
                    ),
                    triage=Triage.RED,
                ))

        return self.result
