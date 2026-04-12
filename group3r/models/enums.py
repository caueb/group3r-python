"""Enumerations used throughout Group3r."""

from enum import Enum, IntEnum


class Triage(IntEnum):
    """Severity levels for findings, from lowest to highest."""
    GREEN = 0
    YELLOW = 1
    RED = 2
    BLACK = 3


class SettingAction(Enum):
    """Action type for a GPO setting."""
    UPDATE = "U"
    CREATE = "C"
    REMOVE = "R"
    ADD = "ADD"
    UNKNOWN = ""


class PolicyType(Enum):
    """Whether a setting applies to Computer or User policy."""
    COMPUTER = "Computer"
    USER = "User"
    PACKAGE = "Package"


class ScriptType(Enum):
    """Type of script in a GPO."""
    LOGON = "Logon"
    LOGOFF = "Logoff"
    STARTUP = "Startup"
    SHUTDOWN = "Shutdown"


class SchedTaskType(Enum):
    """Type of scheduled task."""
    TASK = "Task"
    TASK_V2 = "TaskV2"
    IMMEDIATE_TASK = "ImmediateTask"
    IMMEDIATE_TASK_V2 = "ImmediateTaskV2"


class InterestingIf(Enum):
    """Condition under which a registry key is considered interesting."""
    PRESENT = "Present"
    BAD = "Bad"
    NOT_GOOD = "NotGood"
    NOT_DEFAULT = "NotDefault"
    LESS_THAN_GOOD = "LessThanGood"


class RegKeyValType(IntEnum):
    """Windows registry value types."""
    REG_NONE = 0
    REG_SZ = 1
    REG_EXPAND_SZ = 2
    REG_BINARY = 3
    REG_DWORD = 4
    REG_DWORD_BIG_ENDIAN = 5
    REG_LINK = 6
    REG_MULTI_SZ = 7
    REG_RESOURCE_LIST = 8
    REG_FULL_RESOURCE_DESCRIPTOR = 9
    REG_RESOURCE_REQUIREMENTS_LIST = 10
    REG_QWORD = 11


class RegHive(Enum):
    """Windows registry hives."""
    HKEY_CLASSES_ROOT = "HKEY_CLASSES_ROOT"
    HKEY_CURRENT_USER = "HKEY_CURRENT_USER"
    HKEY_LOCAL_MACHINE = "HKEY_LOCAL_MACHINE"
    HKEY_USERS = "HKEY_USERS"
    HKEY_CURRENT_CONFIG = "HKEY_CURRENT_CONFIG"


class SecurityInheritanceType(Enum):
    """How security settings are inherited."""
    NO_REPLACE = "0"
    CONFIGURE_THEN_INHERIT = "1"
    CONFIGURE_THEN_PROPAGATE = "2"


def parse_setting_action(action_string: str) -> SettingAction:
    """Parse an action string from GPO XML into a SettingAction enum."""
    mapping = {"C": SettingAction.CREATE, "U": SettingAction.UPDATE,
               "R": SettingAction.REMOVE, "ADD": SettingAction.ADD}
    return mapping.get(action_string, SettingAction.UNKNOWN)
