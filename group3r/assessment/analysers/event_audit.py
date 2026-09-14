"""Analyser for Event Audit INF settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import EventAuditSetting
from ...options import AssessmentOptions
from ..analyser import Analyser

_LEVELS = {
    0: "No auditing",
    1: "Success",
    2: "Failure",
    3: "Success and Failure",
}


class EventAuditAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: EventAuditSetting = self.setting
        if setting.audit_level:
            level = _LEVELS.get(setting.audit_level, str(setting.audit_level))
            self.add_finding(GpoFinding(
                finding_reason=f"Non-default event audit policy: {setting.audit_type or 'Unknown'} = {level}",
                finding_detail="Audit policy configured via GptTmpl.inf. Useful for understanding logging on hosts this GPO applies to.",
                triage=Triage.GREEN,
            ))
        return self.result
