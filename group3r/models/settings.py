"""GPO Setting data models - base class and all 23 setting types."""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .enums import (
    PolicyType, RegHive, RegKeyValType, SchedTaskType, ScriptType,
    SecurityInheritanceType, SettingAction, parse_setting_action,
)

logger = logging.getLogger(__name__)

# MS14-025: well-known AES key for GPP cpassword decryption
_GPP_AES_KEY = bytes([
    0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
    0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
    0xf4, 0x96, 0xe8, 0x06, 0xcc, 0x05, 0x79, 0x90,
    0x20, 0x9b, 0x09, 0xa4, 0x33, 0xb6, 0x6c, 0x1b,
])


@dataclass
class GpoSetting:
    """Base class for all GPO setting types."""
    source: str = ""
    policy_type: PolicyType = PolicyType.COMPUTER
    is_morphed: bool = False

    @staticmethod
    def decrypt_cpassword(cpassword: Optional[str]) -> Optional[str]:
        """Decrypt a GPP cpassword (MS14-025) using the well-known AES key."""
        if not cpassword:
            return None
        try:
            # Pad base64 string
            padding_needed = len(cpassword) % 4
            if padding_needed == 1:
                cpassword += "="
            elif padding_needed == 2:
                cpassword += "=="
            elif padding_needed == 3:
                cpassword += "="

            decoded = base64.b64decode(cpassword)
            iv = b"\x00" * 16
            cipher = Cipher(algorithms.AES(_GPP_AES_KEY), modes.CBC(iv))
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(decoded) + decryptor.finalize()
            return decrypted.decode("utf-16-le").rstrip("\x00")
        except Exception as e:
            logger.warning("Failed to decrypt cpassword: %s", e)
            return None


# --- Registry ---

@dataclass
class RegistryValue:
    """A single registry value within a RegistrySetting."""
    value_name: str = ""
    reg_key_val_type: RegKeyValType = RegKeyValType.REG_SZ
    value_sddl_string: str = ""
    value_bytes: Optional[bytes] = None
    value_string: str = ""


@dataclass
class RegistrySetting(GpoSetting):
    """Registry key/value settings from GPO."""
    name: str = ""
    status: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    registry_action: str = ""
    display_decimal: str = ""
    default: str = ""
    changed: Optional[datetime] = None
    hive: RegHive = RegHive.HKEY_LOCAL_MACHINE
    key: str = ""
    key_sddl_string: str = ""
    inheritance: str = ""
    values: list[RegistryValue] = field(default_factory=list)

    def reg_hive_from_string(self, hive_string: str) -> None:
        mapping = {
            "MACHINE": RegHive.HKEY_LOCAL_MACHINE,
            "USER": RegHive.HKEY_CURRENT_USER,
        }
        if hive_string in mapping:
            self.hive = mapping[hive_string]


# --- Scheduled Tasks ---

@dataclass
class SchedTaskPrincipal:
    """Principal (RunAs identity) for a scheduled task."""
    id: str = ""
    user_id: str = ""
    cpassword: str = ""
    password: str = ""
    logon_type: str = ""
    run_level: str = ""


@dataclass
class SchedTaskAction:
    """Base class for scheduled task actions."""
    pass


@dataclass
class SchedTaskExecAction(SchedTaskAction):
    """Execute a command."""
    command: str = ""
    args: str = ""
    working_dir: str = ""


@dataclass
class SchedTaskEmailAction(SchedTaskAction):
    """Send an email."""
    from_addr: str = ""
    to: str = ""
    subject: str = ""
    body: str = ""
    header_fields: str = ""
    attachments: list[str] = field(default_factory=list)
    server: str = ""


@dataclass
class SchedTaskShowMessageAction(SchedTaskAction):
    """Show a message."""
    title: str = ""
    body: str = ""


@dataclass
class SchedTaskSetting(GpoSetting):
    """Scheduled task settings from GPO."""
    name: str = ""
    type: str = ""
    changed: Optional[datetime] = None
    task_type: SchedTaskType = SchedTaskType.TASK
    setting_action: SettingAction = SettingAction.UNKNOWN
    sched_task_action: str = ""
    author: str = ""
    principals: list[SchedTaskPrincipal] = field(default_factory=list)
    description1: str = ""
    comment: str = ""
    duration: str = ""
    wait_timeout: str = ""
    start_only_if_idle: bool = False
    stop_on_idle_end: bool = False
    restart_on_idle: bool = False
    multiple_instances_policy: str = ""
    disallow_start_if_on_batteries: bool = False
    stop_if_going_on_batteries: bool = False
    system_required: bool = False
    allow_hard_terminate: bool = False
    allow_start_on_demand: bool = False
    enabled: bool = False
    hidden: bool = False
    execution_time_limit: str = ""
    priority: int = 0
    actions: list[SchedTaskAction] = field(default_factory=list)
    triggers: list = field(default_factory=list)


# --- Scripts ---

@dataclass
class ScriptSetting(GpoSetting):
    """Script execution settings (logon/logoff/startup/shutdown)."""
    script_type: ScriptType = ScriptType.LOGON
    cmd_line: str = ""
    parameters: str = ""


# --- Privilege Rights ---

@dataclass
class PrivRightSetting(GpoSetting):
    """OS privilege assignments."""
    privilege: str = ""
    trustee_sids: list[str] = field(default_factory=list)
    trustees: list = field(default_factory=list)
    description: str = ""


# --- Group Membership ---

@dataclass
class GroupSettingMember:
    """A member within a GroupSetting."""
    name: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    sid: str = ""
    resolved_name: str = ""


@dataclass
class GroupSetting(GpoSetting):
    """Group membership and permissions."""
    name: str = ""
    new_name: str = ""
    description: str = ""
    group_sid: str = ""
    delete_all_groups: bool = False
    delete_all_users: bool = False
    remove_accounts: bool = False
    action: SettingAction = SettingAction.UNKNOWN
    group_action: str = ""
    members: list[GroupSettingMember] = field(default_factory=list)


# --- Files ---

@dataclass
class FileSetting(GpoSetting):
    """File copy/deployment settings."""
    file_name: str = ""
    status: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    file_action: str = ""
    target_path: str = ""
    from_path: str = ""


@dataclass
class FileSecuritySetting(GpoSetting):
    """File/folder ACL settings."""
    sddl: str = ""
    file_sec_path: str = ""
    security_inheritance_type: SecurityInheritanceType = SecurityInheritanceType.NO_REPLACE


@dataclass
class FolderSetting(GpoSetting):
    """Folder creation/modification settings."""
    name: str = ""
    status: str = ""
    image: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    folder_action: str = ""
    path: str = ""
    read_only: bool = False
    archive: bool = False
    hidden: bool = False


# --- Services ---

@dataclass
class NtServiceSetting(GpoSetting):
    """Windows service configuration."""
    name: str = ""
    sddl: str = ""
    service_name: str = ""
    timeout: str = ""
    startup_type: str = ""
    user_name: str = ""
    cpassword: str = ""
    password: str = ""
    service_action: str = ""
    program: str = ""
    args: str = ""
    action_on_first_failure: str = ""
    append: str = ""
    account_name: str = ""
    reset_fail_count_delay: str = ""
    interact: str = ""


# --- Network ---

@dataclass
class NetworkShareSetting(GpoSetting):
    """Network share definitions."""
    name: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    network_share_action: str = ""
    path: str = ""
    limit_users: str = ""
    abe: str = ""
    all_regular: str = ""
    all_hidden: str = ""
    all_admin_drive: str = ""
    comment: str = ""


@dataclass
class DriveSetting(GpoSetting):
    """Network drive mappings."""
    name: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    drive_action: str = ""
    this_drive: str = ""
    all_drives: str = ""
    user_name: str = ""
    cpassword: str = ""
    password: str = ""
    path: str = ""
    label: str = ""
    persistent: str = ""
    letter: str = ""
    drive_letter: str = ""


@dataclass
class PrinterSetting(GpoSetting):
    """Printer connection settings."""
    name: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    printer_action: str = ""
    path: str = ""
    comment: str = ""
    user_name: str = ""
    cpassword: str = ""
    password: str = ""
    port: str = ""


# --- Data Sources ---

@dataclass
class DataSourceSetting(GpoSetting):
    """Database connection settings."""
    name: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    user_name: str = ""
    cpassword: str = ""
    password: str = ""
    dsn: str = ""
    driver: str = ""
    description: str = ""
    attributes: dict[str, str] = field(default_factory=dict)


# --- Shortcuts ---

@dataclass
class ShortcutSetting(GpoSetting):
    """Shortcut creation settings."""
    name: str = ""
    status: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    shortcut_action: str = ""
    target_type: str = ""
    arguments: str = ""
    icon_path: str = ""
    icon_index: str = ""
    start_in: str = ""
    comment: str = ""
    shortcut_path: str = ""
    target_path: str = ""


# --- Users ---

@dataclass
class UserSetting(GpoSetting):
    """Local user account settings."""
    name: str = ""
    new_name: str = ""
    full_name: str = ""
    user_name: str = ""
    cpassword: str = ""
    password: str = ""
    account_disabled: bool = False
    pw_never_expires: bool = False
    action: SettingAction = SettingAction.UNKNOWN
    user_action: str = ""
    description: str = ""


# --- INI Files ---

@dataclass
class IniFileSetting(GpoSetting):
    """INI file modification settings."""
    name: str = ""
    path: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    ini_file_action: str = ""
    section: str = ""
    value: str = ""
    property: str = ""


# --- Security Policy ---

@dataclass
class SystemAccessSetting(GpoSetting):
    """System access / password policy settings."""
    setting_name: str = ""
    value_string: str = ""


@dataclass
class KerbPolicySetting(GpoSetting):
    """Kerberos policy settings."""
    key: str = ""
    value: str = ""


@dataclass
class EventAuditSetting(GpoSetting):
    """Audit policy settings."""
    audit_type: str = ""
    audit_level: int = 0


# --- Devices ---

@dataclass
class DeviceSetting(GpoSetting):
    """Device/hardware settings."""
    name: str = ""
    device_action: str = ""
    device_class: str = ""
    device_class_guid: str = ""
    device_type: str = ""
    device_type_id: str = ""


# --- Environment Variables ---

@dataclass
class EnvVarSetting(GpoSetting):
    """Environment variable settings."""
    name: str = ""
    status: str = ""
    action: SettingAction = SettingAction.UNKNOWN
    env_var_action: str = ""


# --- Network Options ---

@dataclass
class NetOptionSetting(GpoSetting):
    """Network options (placeholder)."""
    pass


# --- Packages ---

@dataclass
class PackageSetting(GpoSetting):
    """Software package deployment (MSI/APPX)."""
    display_name: str = ""
    distinguished_name: str = ""
    msi_file_list: list[str] = field(default_factory=list)
    created_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    ads_path: str = ""
    product_code: str = ""
    cn: str = ""
    upgrade_product_code: str = ""
    msi_script_name: str = ""
    package_action: str = ""
    parent_gpo: str = ""
