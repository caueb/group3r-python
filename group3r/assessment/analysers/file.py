"""Analyser for File deployment settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import FileSetting
from ...options import AssessmentOptions
from ..analyser import Analyser


class FileAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: FileSetting = self.setting

        if setting.from_path:
            target = setting.target_path or ""
            if setting.from_path.startswith("\\\\"):
                # Network source - RED (writable file to be copied)
                self.add_finding(GpoFinding(
                    finding_reason=f"Writable file identified at {setting.from_path} to be copied to {target}",
                    finding_detail=(
                        "This GPO setting will copy a file from point A to point B. "
                        "If it's a config file you might be able to modify how an app "
                        "executes. If it's a script you might be able to modify it "
                        "before it runs as someone else, if it's an Office doc that "
                        "supports macros... you get the idea."
                    ),
                    triage=Triage.RED,
                ))
            else:
                # Local/relative source - YELLOW (missing source with writable parent)
                self.add_finding(GpoFinding(
                    finding_reason=(
                        f"A GPP File GPO setting is missing its source file, "
                        f"and it has a writable parent dir. "
                        f"The original target path was {setting.from_path}. "
                        f"Depending on the file type you might be able to do something fun?"
                    ),
                    finding_detail="Recreate the missing parts of the path in the parent dir, put bad guy stuff in the file, cross your fingers.",
                    triage=Triage.YELLOW,
                ))

        return self.result
