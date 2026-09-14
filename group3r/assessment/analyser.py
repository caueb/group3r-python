"""Base Analyser and AnalyserFactory for routing settings to the correct analyser."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Optional

from ..models.enums import Triage
from ..models.findings import GpoFinding, SettingResult
from ..models.settings import (
    DataSourceSetting, DriveSetting, EventAuditSetting, FileSetting,
    FileSecuritySetting, GpoSetting, GroupSetting, KerbPolicySetting,
    NetworkShareSetting, NtServiceSetting, PackageSetting, PrinterSetting,
    PrivRightSetting, RegistrySetting, SchedTaskSetting, ScriptSetting,
    ShortcutSetting, SystemAccessSetting, UserSetting,
)
from ..options import AssessmentOptions

logger = logging.getLogger(__name__)


class Analyser(ABC):
    """Abstract base class for GPO setting analysers."""

    def __init__(self, setting: GpoSetting, min_triage: Triage = Triage.GREEN):
        self.setting = setting
        self.min_triage = min_triage
        self.result = SettingResult(setting=setting)

    @abstractmethod
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        """Analyse the setting and return findings."""
        ...

    def add_finding(self, finding: GpoFinding) -> None:
        """Add a finding if it meets the minimum triage level."""
        if finding.triage >= self.min_triage:
            self.result.findings.append(finding)


def get_analyser(setting: GpoSetting) -> Optional[Analyser]:
    """Factory function: return the appropriate Analyser for a GpoSetting, or None."""
    from .analysers.priv_right import PrivRightAnalyser
    from .analysers.group import GroupAnalyser
    from .analysers.registry import RegistryAnalyser
    from .analysers.sched_task import SchedTaskAnalyser
    from .analysers.script import ScriptAnalyser
    from .analysers.file import FileAnalyser
    from .analysers.nt_service import NtServiceAnalyser
    from .analysers.shortcut import ShortcutAnalyser
    from .analysers.printer import PrinterAnalyser
    from .analysers.data_source import DataSourceAnalyser
    from .analysers.system_access import SystemAccessAnalyser
    from .analysers.kerberos_policy import KerbPolicyAnalyser
    from .analysers.package import PackageAnalyser
    from .analysers.network_share import NetworkShareAnalyser
    from .analysers.drive import DriveAnalyser
    from .analysers.user import UserAnalyser
    from .analysers.file_sec import FileSecAnalyser
    from .analysers.event_audit import EventAuditAnalyser

    _ANALYSER_MAP: dict[type, type[Analyser]] = {
        PrivRightSetting: PrivRightAnalyser,
        GroupSetting: GroupAnalyser,
        RegistrySetting: RegistryAnalyser,
        SchedTaskSetting: SchedTaskAnalyser,
        ScriptSetting: ScriptAnalyser,
        FileSetting: FileAnalyser,
        NtServiceSetting: NtServiceAnalyser,
        ShortcutSetting: ShortcutAnalyser,
        PrinterSetting: PrinterAnalyser,
        DataSourceSetting: DataSourceAnalyser,
        SystemAccessSetting: SystemAccessAnalyser,
        KerbPolicySetting: KerbPolicyAnalyser,
        PackageSetting: PackageAnalyser,
        NetworkShareSetting: NetworkShareAnalyser,
        DriveSetting: DriveAnalyser,
        UserSetting: UserAnalyser,
        FileSecuritySetting: FileSecAnalyser,
        EventAuditSetting: EventAuditAnalyser,
    }

    analyser_cls = _ANALYSER_MAP.get(type(setting))
    if analyser_cls:
        return analyser_cls(setting)
    return None
