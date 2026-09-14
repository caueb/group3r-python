"""Analyser for Script settings."""

from __future__ import annotations

import re

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import ScriptSetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..path_analyser import analyse_setting_path
from ..path_utils import is_drive_letter_path, is_unc, path_exists, resolve_script_path

_PASSWORD_PATTERN = re.compile(
    r"(pass|pw|cred|secret|key|token|\-p\s|/p\s)", re.IGNORECASE
)


class ScriptAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: ScriptSetting = self.setting
        script_type = setting.script_type.value if setting.script_type else "Script"

        if setting.parameters and _PASSWORD_PATTERN.search(setting.parameters):
            self.add_finding(GpoFinding(
                finding_reason=f"{script_type} script has an arguments setting that looks like it might have a password in it?",
                finding_detail=f"Arguments were: {setting.parameters}",
                triage=Triage.YELLOW,
            ))

        if not setting.cmd_line:
            return self.result

        cmd_line = setting.cmd_line.strip()
        assessed = resolve_script_path(cmd_line, setting.source, script_type)
        pr = analyse_setting_path(options, assessed if is_unc(assessed) else cmd_line)

        if pr.file_writable:
            self.add_finding(GpoFinding(
                finding_reason=f"Writable {script_type} script file identified at {pr.path}",
                finding_detail=(
                    "This script will run in the context of the users/computers "
                    "to which this GPO is applied. Change the script, get command "
                    "exec as those users/computers."
                ),
                triage=Triage.BLACK,
                path_findings=[pr],
            ))
        elif pr.parent_directory_writable:
            self.add_finding(GpoFinding(
                finding_reason=f"Missing {script_type} script with a writable parent dir. The original target path was {assessed or cmd_line}",
                finding_detail=(
                    "Recreate the missing parts of the path in the parent dir, "
                    "put your code in the script. It will then run in the context "
                    "of the users/computers to which this GPO is applied."
                ),
                triage=Triage.RED,
                path_findings=[pr],
            ))
        elif is_unc(cmd_line) or is_unc(assessed):
            self.add_finding(GpoFinding(
                finding_reason=f"Network-hosted {script_type} script identified at {assessed or cmd_line}",
                finding_detail=(
                    "This script will run in the context of the users/computers "
                    "to which this GPO is applied. If the share or file is writable, "
                    "replace the script for code execution. Writability was not verified."
                ),
                triage=Triage.RED,
                path_findings=[pr],
            ))
        elif not path_exists(assessed) and not path_exists(cmd_line):
            if is_drive_letter_path(cmd_line):
                return self.result
            self.add_finding(GpoFinding(
                finding_reason=f"Referenced {script_type} script was not found at {assessed or cmd_line}",
                finding_detail=(
                    "If a parent directory of this path is writable, recreating "
                    "the missing script would give code execution as the GPO target."
                ),
                triage=Triage.YELLOW,
            ))

        return self.result
