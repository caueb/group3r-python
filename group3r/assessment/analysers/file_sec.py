"""Analyser for INF File Security ACL settings."""

from __future__ import annotations

import logging

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import FileSecuritySetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..trustee_match import match_trustee

logger = logging.getLogger(__name__)

_WRITE_RIGHTS = {
    "GENERIC_ALL", "GENERIC_WRITE", "FILE_ALL", "FILE_WRITE", "WRITE_DAC",
    "WRITE_OWNER", "WRITE_DATA", "APPEND_DATA", "DELETE_CHILD", "Owner",
    "ALL_ACCESS", "STANDARD_RIGHTS_ALL",
}


class FileSecAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: FileSecuritySetting = self.setting
        if not setting.sddl:
            return self.result

        from ...sddl.parser import SddlDescriptor
        from ...sddl.constants import SecurableObjectType
        from ..sddl_analyser import analyse_sddl

        try:
            parsed = SddlDescriptor(setting.sddl, SecurableObjectType.FILE)
            aces = analyse_sddl(parsed)
        except Exception as e:
            logger.debug("Failed to parse file security SDDL: %s", e)
            return self.result

        path = setting.file_sec_path or "(unknown path)"
        for ace in aces:
            if ace.ace_type != "Allow":
                continue
            if not any(r in _WRITE_RIGHTS for r in ace.rights):
                continue
            to = match_trustee(options, ace.trustee, ace.trustee_sid)
            if not to or to.get("high_priv"):
                continue
            if to.get("low_priv") or to.get("target"):
                self.add_finding(GpoFinding(
                    finding_reason="File security setting grants write access to a low-priv trustee.",
                    finding_detail=f"Path: {path}, Trustee: {to.get('display_name') or ace.trustee}",
                    triage=Triage.RED,
                    acl_result=[ace],
                ))
        return self.result
