"""Analyser for Scheduled Task settings."""

from __future__ import annotations

import re

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import (
    SchedTaskEmailAction, SchedTaskExecAction, SchedTaskSetting,
)
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..path_analyser import analyse_setting_path
from ..path_utils import is_unc

_PASSWORD_PATTERN = re.compile(
    r"(pass|pw|cred|secret|key|token|\-p\s|/p\s)", re.IGNORECASE
)


class SchedTaskAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: SchedTaskSetting = self.setting

        for principal in setting.principals:
            cpassword = principal.cpassword
            if cpassword:
                password = setting.decrypt_cpassword(cpassword)
                self.add_finding(GpoFinding(
                    finding_reason=f"Group Policy Preferences password found:{password or cpassword}",
                    finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                    triage=Triage.BLACK,
                ))

        for action in setting.actions:
            if isinstance(action, SchedTaskExecAction):
                if action.working_dir and is_unc(action.working_dir):
                    pr = analyse_setting_path(options, action.working_dir)
                    if pr.directory_writable or pr.parent_directory_writable:
                        self.add_finding(GpoFinding(
                            finding_reason="Scheduled task exec action is configured to use a working directory that you can write to.",
                            finding_detail=f"You might be able to pull some DLL sideloading shenanigans in {action.working_dir}",
                            triage=Triage.YELLOW,
                            path_findings=[pr],
                        ))
                    else:
                        self.add_finding(GpoFinding(
                            finding_reason="Scheduled task exec action is configured to use a working directory on a network path.",
                            finding_detail=f"You might be able to pull some DLL sideloading shenanigans in {action.working_dir} if it is writable. Writability was not verified.",
                            triage=Triage.YELLOW,
                            path_findings=[pr],
                        ))

                if action.command and is_unc(action.command):
                    pr = analyse_setting_path(options, action.command)
                    if pr.file_writable or pr.directory_writable or pr.parent_directory_writable:
                        self.add_finding(GpoFinding(
                            finding_reason="Scheduled Task execute action points at a file that you can modify.",
                            finding_detail=f"It points to {action.command}, so maybe see what happens if you modify that file.",
                            triage=Triage.RED,
                            path_findings=[pr],
                        ))
                    else:
                        self.add_finding(GpoFinding(
                            finding_reason="Scheduled Task execute action points at a network path.",
                            finding_detail=f"It points to {action.command}. If that file is writable, you can modify what the task runs. Writability was not verified.",
                            triage=Triage.RED,
                            path_findings=[pr],
                        ))

                if action.args and _PASSWORD_PATTERN.search(action.args):
                    self.add_finding(GpoFinding(
                        finding_reason="Scheduled Task exec action has an arguments setting that looks like it might have a password in it?",
                        finding_detail=f"Arguments were: {action.args}",
                        triage=Triage.YELLOW,
                    ))

            elif isinstance(action, SchedTaskEmailAction):
                if action.attachments:
                    attachments_str = ", ".join(action.attachments)
                    self.add_finding(GpoFinding(
                        finding_reason="Scheduled Task is emailing attachments. Could be interesting.",
                        finding_detail=f"Check out {attachments_str}",
                        triage=Triage.GREEN,
                    ))

        return self.result
