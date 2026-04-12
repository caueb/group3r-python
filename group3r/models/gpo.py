"""GPO, GPOAttributes, and GPOLink data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .settings import GpoSetting


@dataclass
class GPOLink:
    """Represents where a GPO is linked (OU path + enforcement)."""
    link_path: str = ""
    link_enforced: str = ""


@dataclass
class GPOAttributes:
    """Metadata attributes of a Group Policy Object."""
    is_morphed_gpo: bool = False
    gpo_links: list[GPOLink] = field(default_factory=list)
    ads_path: str = ""
    display_name: str = ""
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    nt_security_descriptor: str = ""
    distinguished_name: str = ""
    path_in_sysvol: str = ""
    uid: str = ""
    version_number: str = ""
    computer_policy_enabled: bool = True
    user_policy_enabled: bool = True


@dataclass
class GPO:
    """Represents a Group Policy Object with its attributes, files, and parsed settings."""
    attributes: GPOAttributes = field(default_factory=GPOAttributes)
    gpo_files: list[str] = field(default_factory=list)
    settings: list[GpoSetting] = field(default_factory=list)

    def __init__(self, uid: str = "", path_in_sysvol: str = "", morphed: bool = False):
        self.attributes = GPOAttributes(
            uid=uid,
            path_in_sysvol=path_in_sysvol,
            is_morphed_gpo=morphed,
        )
        self.gpo_files = []
        self.settings = []
