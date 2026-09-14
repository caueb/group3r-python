"""Finding and result data models for GPO assessment output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .enums import Triage
from .gpo import GPOAttributes
from .settings import GpoSetting


@dataclass
class SimpleAce:
    """Simplified Access Control Entry."""
    ace_type: str = ""  # "Allow" or "Deny"
    rights: list[str] = field(default_factory=list)
    trustee: str = ""
    trustee_sid: str = ""


@dataclass
class PathResult:
    """Result of analyzing a filesystem path."""
    path: str = ""
    file_exists: bool = False
    file_writable: bool = False
    directory_exists: bool = False
    directory_writable: bool = False
    parent_directory_writable: bool = False
    snaffler_findings: list[str] = field(default_factory=list)


@dataclass
class GpoFinding:
    """A single security finding from GPO analysis."""
    finding_reason: str = ""
    finding_detail: str = ""
    triage: Triage = Triage.GREEN
    path_findings: list[PathResult] = field(default_factory=list)
    acl_result: list[SimpleAce] = field(default_factory=list)


@dataclass
class SettingResult:
    """Result of analyzing a single GPO setting."""
    setting: Optional[GpoSetting] = None
    findings: list[GpoFinding] = field(default_factory=list)


@dataclass
class GpoResult:
    """Aggregated result for an entire GPO."""
    attributes: Optional[GPOAttributes] = None
    gpo_acl_results: list[SimpleAce] = field(default_factory=list)
    gpo_attribute_findings: list[GpoFinding] = field(default_factory=list)
    setting_results: list[SettingResult] = field(default_factory=list)
