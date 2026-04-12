"""GrouperOptions and AssessmentOptions configuration."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models.enums import Triage


# Rights that indicate interesting/exploitable permissions
INTERESTING_RIGHTS: list[str] = [
    "Owner",
    "CREATE_CHILD",
    "GENERIC_WRITE",
    "GENERIC_ALL",
    "WRITE_ATTRIBUTES",
    "WRITE_PROPERTIES",
    "WRITE_PROPERTY",
    "APPEND_DATA",
    "WRITE_DATA",
    "ALL_ACCESS",
    "DELETE_CHILD",
    "CREATE_CHILD",
    "WRITE_TREE",
    "FILE_WRITE",
    "FILE_ALL",
    "KEY_WRITE",
    "KEY_ALL",
    "STANDARD_RIGHTS_ALL",
    "STANDARD_DELETE",
    "DELETE_TREE",
    "ADD_FILE",
    "ADD_SUBDIRECTORY",
    "CREATE_PIPE_INSTANCE",
    "WRITE",
    "CREATE_LINK",
    "SET_VALUE",
    "WRITE_DAC",
    "WRITE_OWNER",
]


@dataclass
class AssessmentOptions:
    """Options controlling assessment analysis."""
    min_triage: Triage = Triage.GREEN
    interesting_rights: list[str] = field(default_factory=lambda: list(INTERESTING_RIGHTS))
    priv_rights: list[dict] = field(default_factory=list)
    trustee_options: list[dict] = field(default_factory=list)
    reg_keys: list[dict] = field(default_factory=list)

    def __post_init__(self):
        from .data.priv_rights import PRIV_RIGHTS
        from .data.trustees import TRUSTEE_OPTIONS
        if not self.priv_rights:
            self.priv_rights = PRIV_RIGHTS
        if not self.trustee_options:
            self.trustee_options = TRUSTEE_OPTIONS
        try:
            from .data.reg_keys import REG_KEYS
            if not self.reg_keys:
                self.reg_keys = REG_KEYS
        except ImportError:
            pass


@dataclass
class GrouperOptions:
    """Main options for Group3r operation."""
    offline_mode: bool = False
    sysvol_path: str = ""
    target_domain: str = ""
    target_dc: str = ""
    dc_host: str = ""
    username: str = ""
    password: str = ""
    hashes: str = ""
    use_kerberos: bool = False
    auth_domain: str = ""  # extracted from UPN in username (user@domain)
    verbose: bool = False
    stdout: bool = True
    outfile: str = ""
    findings_only: bool = False
    enabled_only: bool = False
    current_only: bool = False
    min_triage: Triage = Triage.GREEN
    json_output: bool = False
    max_sysvol_threads: int = 10
    max_sysvol_queue: int = 0
    assessment_options: AssessmentOptions = field(default_factory=AssessmentOptions)
