"""Analyser for File deployment settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import FileSetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..path_analyser import analyse_setting_path
from ..path_utils import is_drive_letter_path, is_unc


class FileAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: FileSetting = self.setting

        if not setting.from_path or not setting.target_path:
            return self.result

        from_path = setting.from_path
        target = setting.target_path

        if is_drive_letter_path(from_path):
            return self.result

        pr = analyse_setting_path(options, from_path)

        if pr.file_writable:
            self.add_finding(GpoFinding(
                finding_reason=f"Writable file identified at {from_path} to be copied to {target}",
                finding_detail=(
                    "This GPO setting will copy a file from point A to point B. "
                    "If it's a config file you might be able to modify how an app "
                    "executes. If it's a script you might be able to modify it "
                    "before it runs as someone else, if it's an Office doc that "
                    "supports macros... you get the idea."
                ),
                triage=Triage.RED,
                path_findings=[pr],
            ))
        elif pr.parent_directory_writable:
            self.add_finding(GpoFinding(
                finding_reason=(
                    f"A GPP File GPO setting is missing its source file, "
                    f"and it has a writable parent dir. "
                    f"The original target path was {from_path}."
                ),
                finding_detail="Recreate the missing parts of the path in the parent dir, put bad guy stuff in the file, cross your fingers.",
                triage=Triage.YELLOW,
                path_findings=[pr],
            ))
        elif is_unc(from_path):
            self.add_finding(GpoFinding(
                finding_reason=f"Network file copy source identified at {from_path} to be copied to {target}",
                finding_detail=(
                    "This GPO setting will copy a file from point A to point B. "
                    "If the source is writable you may be able to modify a config, "
                    "script, or macro document before it is deployed. Writability was not verified."
                ),
                triage=Triage.RED,
                path_findings=[pr],
            ))

        return self.result
