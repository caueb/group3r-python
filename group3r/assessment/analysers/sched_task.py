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

_PASSWORD_PATTERN = re.compile(
    r"(pass|pw|cred|secret|key|token|\-p\s|/p\s)", re.IGNORECASE
)


class SchedTaskAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: SchedTaskSetting = self.setting

        # Check principals for cpassword
        for principal in setting.principals:
            if principal.cpassword:
                password = setting.decrypt_cpassword(principal.cpassword)
                self.add_finding(GpoFinding(
                    finding_reason=f"Group Policy Preferences password found:{password or principal.cpassword}",
                    finding_detail="Refer to MS14-025 and https://adsecurity.org/?p=63",
                    triage=Triage.BLACK,
                ))

        # Check actions
        for action in setting.actions:
            if isinstance(action, SchedTaskExecAction):
                # Check working directory - YELLOW
                if action.working_dir:
                    self.add_finding(GpoFinding(
                        finding_reason="Scheduled task exec action is configured to use a working directory that you can write to.",
                        finding_detail=f"You might be able to pull some DLL sideloading shenanigans in {action.working_dir}",
                        triage=Triage.YELLOW,
                    ))

                # Check command path - RED
                if action.command:
                    self.add_finding(GpoFinding(
                        finding_reason="Scheduled Task execute action points at a file that you can modify.",
                        finding_detail=f"It points to {action.command}, so maybe see what happens if you modify that file.",
                        triage=Triage.RED,
                    ))

                # Check arguments for password-like content - YELLOW
                if action.args and _PASSWORD_PATTERN.search(action.args):
                    self.add_finding(GpoFinding(
                        finding_reason="Scheduled Task exec action has an arguments setting that looks like it might have a password in it?",
                        finding_detail=f"Arguments were: {action.args}",
                        triage=Triage.YELLOW,
                    ))

            elif isinstance(action, SchedTaskEmailAction):
                # Check email attachments
                if action.attachments:
                    attachments_str = ", ".join(action.attachments)
                    self.add_finding(GpoFinding(
                        finding_reason="Scheduled Task is emailing attachments. Could be interesting.",
                        finding_detail=f"Check out {attachments_str}",
                        triage=Triage.GREEN,
                    ))

        return self.result
