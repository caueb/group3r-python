"""Output formatter matching the original Group3r NiceGpoPrinter format exactly.

Produces column-aligned markdown tables with \\___  tail markers at column 0,
content indented by 4 spaces, identical to the C# NiceGpoPrinter output.
"""

from __future__ import annotations

import io
import textwrap
from typing import Optional

from ..models.enums import Triage
from ..models.findings import GpoFinding, GpoResult, SettingResult
from ..models.gpo import GPOAttributes
from ..models.settings import (
    DataSourceSetting, DeviceSetting, DriveSetting, EnvVarSetting,
    EventAuditSetting, FileSetting, FileSecuritySetting, FolderSetting,
    GpoSetting, GroupSetting, IniFileSetting, KerbPolicySetting,
    NetOptionSetting, NetworkShareSetting, NtServiceSetting,
    PackageSetting, PrinterSetting, PrivRightSetting, RegistrySetting,
    SchedTaskExecAction, SchedTaskEmailAction, SchedTaskPrincipal,
    SchedTaskSetting, SchedTaskShowMessageAction, ScriptSetting,
    ShortcutSetting, SystemAccessSetting, UserSetting,
)

_TRIAGE_NAMES = {
    Triage.GREEN: "Green",
    Triage.YELLOW: "Yellow",
    Triage.RED: "Red",
    Triage.BLACK: "Black",
}

_WRAP_WIDTH = 80


def format_gpo_result(result: GpoResult, findings_only: bool = False) -> str:
    """Format a single GpoResult to the original Group3r output format."""
    sb = io.StringIO()
    attrs = result.attributes
    if not attrs:
        return ""

    # GPO header table (no indent, at column 0)
    display = attrs.display_name or "(No Display Name)"
    uid = attrs.uid or ""
    morphed = "Morphed" if attrs.is_morphed_gpo else "Current"
    gpo_label = f"{display} {uid} {morphed}"

    rows = []
    if attrs.created_date:
        rows.append(("Date Created", str(attrs.created_date)))
    if attrs.modified_date:
        rows.append(("Date Modified", str(attrs.modified_date)))
    if attrs.path_in_sysvol:
        rows.append(("Path in SYSVOL", attrs.path_in_sysvol))
    rows.append(("Computer Policy", "Enabled" if attrs.computer_policy_enabled else "Disabled"))
    rows.append(("User Policy", "Enabled" if attrs.user_policy_enabled else "Disabled"))
    for link in (attrs.gpo_links or []):
        enforced = f" ({link.link_enforced})" if link.link_enforced else ""
        rows.append(("Link", f"{link.link_path}{enforced}"))

    sb.write(_md_table("GPO", gpo_label, rows))

    # GPO-level findings
    for finding in result.gpo_attribute_findings:
        sb.write(_format_finding_block(finding))

    # Settings
    for sr in result.setting_results:
        if findings_only and not sr.findings:
            continue
        setting_str = _format_setting(sr.setting)
        if setting_str:
            has_findings = bool(sr.findings)
            sb.write(_format_setting_block(setting_str, trailing_blank=not has_findings))

        for finding in sr.findings:
            sb.write(_format_finding_block(finding))

    sb.write("\n")
    return sb.getvalue()


def _format_setting_block(table_str: str, trailing_blank: bool = True) -> str:
    """Wrap a setting table with \\___  marker at col 0 and 4-space indent.

    trailing_blank: add a blank line after the table. Set to False when
    findings follow immediately (the finding block has its own \\___).
    """
    sb = io.StringIO()
    sb.write("\\___\n")
    for line in table_str.splitlines(keepends=True):
        sb.write(f"    {line}")
    if trailing_blank:
        sb.write("\n")
    return sb.getvalue()


def _format_finding_block(finding: GpoFinding) -> str:
    """Wrap a finding table with \\___  marker at col 0 and 8-space indent."""
    triage_name = _TRIAGE_NAMES.get(finding.triage, str(finding.triage.value))
    rows = []
    if finding.finding_reason:
        rows.append(("Reason", finding.finding_reason))
    if finding.finding_detail:
        rows.append(("Detail", finding.finding_detail))
    table_str = _md_table("Finding", triage_name, rows)

    sb = io.StringIO()
    sb.write("    \\___\n")
    for line in table_str.splitlines(keepends=True):
        sb.write(f"        {line}")
    sb.write("\n")
    return sb.getvalue()


def _format_setting(setting: Optional[GpoSetting]) -> str:
    """Format a setting as a markdown table matching NiceGpoPrinter."""
    if setting is None:
        return ""

    # Build header
    policy = "Computer Policy"
    if hasattr(setting, "policy_type"):
        from ..models.enums import PolicyType
        pt = setting.policy_type
        if pt == PolicyType.USER:
            policy = "User Policy"
        elif pt == PolicyType.PACKAGE:
            policy = "Package Policy"

    morphed = " - Morphed" if setting.is_morphed else ""
    header_left = f"Setting - {policy}{morphed}"

    setting_type = type(setting).__name__.replace("Setting", "")
    # Match original C# type names
    type_map = {
        "SchedTask": "Scheduled Task",
        "NtService": "Service",
        "PrivRight": "User Rights Assignment",
        "SystemAccess": "System Access",
        "KerbPolicy": "Kerberos Policy",
        "FileSecurity": "File Security",
        "EnvVar": "Environment Variable",
        "NetworkShare": "Network Share",
        "NetOption": "Network Option",
        "IniFile": "INI File",
    }
    setting_type = type_map.get(setting_type, setting_type)

    rows = _get_setting_rows(setting)
    return _md_table(header_left, setting_type, rows)


def _get_setting_rows(setting: GpoSetting) -> list[tuple[str, str]]:
    """Extract display rows for each setting type, matching C# NiceGpoPrinter."""
    rows: list[tuple[str, str]] = []

    if isinstance(setting, RegistrySetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        key_display = f"{setting.hive.value}\\{setting.key}" if setting.key else ""
        _add(rows, "Key", key_display)
        for v in setting.values:
            _add(rows, "Value Name", v.value_name)
            _add(rows, "Value Type", v.reg_key_val_type.name if v.reg_key_val_type else "")
            _add(rows, "Value String", v.value_string)

    elif isinstance(setting, PrivRightSetting):
        _add(rows, "Privilege", setting.privilege)
        first = True
        for t in setting.trustees:
            label = "Trustee" if first else ""
            display = t.display_name or t.sid
            if display == "Failed to resolve SID." and t.sid:
                display = t.sid
            _add(rows, label, display)
            first = False

    elif isinstance(setting, GroupSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        _add(rows, "NewName", setting.new_name)
        if setting.delete_all_groups:
            _add(rows, "Delete All Groups", "True")
        if setting.delete_all_users:
            _add(rows, "Delete All Users", "True")
        if setting.remove_accounts:
            _add(rows, "Remove Accounts", "True")
        for m in setting.members:
            name = m.name or m.sid or ""
            action = _action_word(m.action) if m.action else ""
            _add(rows, "Member", f"{name} ({action})" if action else name)

    elif isinstance(setting, SchedTaskSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Task Type", setting.task_type.value if setting.task_type else "")
        _add(rows, "Description", setting.description1)
        _add(rows, "Enabled", str(setting.enabled))
        for p in setting.principals:
            _add(rows, "Principal", p.user_id or "")
            _add(rows, "Cpassword", p.cpassword)
            _add(rows, "Password", p.password)
        for a in setting.actions:
            if isinstance(a, SchedTaskExecAction):
                _add(rows, "Command", a.command)
                _add(rows, "Args", a.args)
                _add(rows, "Working Dir", a.working_dir)
            elif isinstance(a, SchedTaskEmailAction):
                _add(rows, "Email To", a.to)
                _add(rows, "Email From", a.from_addr)
                _add(rows, "Email Subject", a.subject)
            elif isinstance(a, SchedTaskShowMessageAction):
                _add(rows, "Message Title", a.title)
                _add(rows, "Message Body", a.body)

    elif isinstance(setting, ScriptSetting):
        _add(rows, "Script Type", setting.script_type.value if setting.script_type else "")
        _add(rows, "CmdLine", setting.cmd_line)
        _add(rows, "Args", setting.parameters)

    elif isinstance(setting, FileSetting):
        _add(rows, "Action", _action_display(setting))
        _add(rows, "FileName", setting.file_name)
        _add(rows, "FromPath", setting.from_path)
        _add(rows, "TargetPath", setting.target_path)

    elif isinstance(setting, NtServiceSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Service Name", setting.service_name)
        startup = {"0": "Boot", "1": "System", "2": "Automatic",
                    "3": "Manual", "4": "Disabled"}.get(
                        setting.startup_type or "", setting.startup_type or "")
        _add(rows, "Startup Type", startup)
        _add(rows, "Program", setting.program)
        _add(rows, "Args", setting.args)
        _add(rows, "UserName", setting.user_name)
        _add(rows, "Cpassword", setting.cpassword)
        _add(rows, "Password", setting.password)

    elif isinstance(setting, PrinterSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        _add(rows, "Comment", setting.comment)
        _add(rows, "Path", setting.path)
        _add(rows, "UserName", setting.user_name)
        _add(rows, "Cpassword", setting.cpassword)
        _add(rows, "Password", setting.password)

    elif isinstance(setting, DriveSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        _add(rows, "Path", setting.path)
        _add(rows, "Label", setting.label)
        _add(rows, "UserName", setting.user_name)
        _add(rows, "Cpassword", setting.cpassword)
        _add(rows, "Password", setting.password)

    elif isinstance(setting, DataSourceSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        _add(rows, "Description", setting.description)
        _add(rows, "Driver", setting.driver)
        _add(rows, "UserName", setting.user_name)
        _add(rows, "Cpassword", setting.cpassword)
        _add(rows, "Password", setting.password)

    elif isinstance(setting, ShortcutSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        _add(rows, "Comment", setting.comment)
        _add(rows, "Shortcut Path", setting.shortcut_path)
        _add(rows, "Target Type", setting.target_type)
        _add(rows, "Target Path", setting.target_path)
        _add(rows, "Arguments", setting.arguments)
        _add(rows, "IconPath", setting.icon_path)
        _add(rows, "IconIndex", setting.icon_index)
        _add(rows, "Status", setting.status)

    elif isinstance(setting, UserSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", _action_display(setting))
        _add(rows, "UserName", setting.user_name)
        _add(rows, "NewName", setting.new_name)
        _add(rows, "FullName", setting.full_name)
        _add(rows, "Description", setting.description)
        _add(rows, "Cpassword", setting.cpassword)
        _add(rows, "Password", setting.password)
        if setting.pw_never_expires:
            _add(rows, "PwNeverExpires", "True")

    elif isinstance(setting, PackageSetting):
        _add(rows, "Display Name", setting.display_name)
        if setting.created_date:
            _add(rows, "CreatedDate", str(setting.created_date))
        _add(rows, "Action", setting.package_action)
        for f in setting.msi_file_list:
            _add(rows, "File", f)
        _add(rows, "Product Code", setting.product_code)
        _add(rows, "Upgrade Product Code", setting.upgrade_product_code)

    elif isinstance(setting, KerbPolicySetting):
        _add(rows, setting.key, setting.value)

    elif isinstance(setting, SystemAccessSetting):
        _add(rows, setting.setting_name, setting.value_string)

    elif isinstance(setting, NetworkShareSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Action", setting.network_share_action or "")
        _add(rows, "Path", setting.path)
        _add(rows, "Comment", setting.comment)

    elif isinstance(setting, IniFileSetting):
        _add(rows, "Path", setting.path)
        _add(rows, "Section", setting.section)
        _add(rows, "Property", setting.property)
        _add(rows, "Value", setting.value)

    elif isinstance(setting, EnvVarSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Status", setting.status)

    elif isinstance(setting, FolderSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Path", setting.path)

    elif isinstance(setting, FileSecuritySetting):
        _add(rows, "Path", setting.file_sec_path)
        _add(rows, "SDDL", setting.sddl)

    elif isinstance(setting, DeviceSetting):
        _add(rows, "Name", setting.name)
        _add(rows, "Device Class", setting.device_class)

    return rows


def _add(rows: list[tuple[str, str]], key: str, value: str) -> None:
    """Add a row only if the value is non-empty."""
    if value:
        rows.append((key, value))


def _action_display(setting) -> str:
    """Get the human-readable action name (Update/Create/Remove, not U/C/R)."""
    from ..models.enums import SettingAction
    # Try the type-specific action string first
    for attr in ("registry_action", "file_action", "folder_action",
                 "group_action", "drive_action", "printer_action",
                 "shortcut_action", "user_action", "network_share_action",
                 "sched_task_action", "ini_file_action", "env_var_action"):
        val = getattr(setting, attr, "")
        if val:
            return val

    action = getattr(setting, "action", None)
    if action:
        return _action_word(action)
    return ""


def _action_word(action) -> str:
    """Convert SettingAction enum to word."""
    from ..models.enums import SettingAction
    mapping = {
        SettingAction.UPDATE: "Update",
        SettingAction.CREATE: "Create",
        SettingAction.REMOVE: "Remove",
        SettingAction.ADD: "Add",
    }
    return mapping.get(action, "")


# --- Column-aligned markdown table (matching ConsoleTables.ToMarkDownString) ---

def _md_table(header_left: str, header_right: str,
              rows: list[tuple[str, str]]) -> str:
    """Build a column-aligned markdown table matching the original C# output."""
    # Compute column widths
    all_rows = [(header_left, header_right)]

    # Pre-process: word-wrap long values and expand into multi-line rows
    expanded: list[tuple[str, str]] = []
    for key, value in rows:
        if len(value) > _WRAP_WIDTH:
            wrapped = _word_wrap(value, _WRAP_WIDTH)
            for i, line in enumerate(wrapped):
                expanded.append((key if i == 0 else "", line))
        else:
            expanded.append((key, value))

    all_rows.extend(expanded)

    col1_width = max(len(r[0]) for r in all_rows)
    col2_width = max(len(r[1]) for r in all_rows)

    # Ensure minimum width
    col1_width = max(col1_width, 3)
    col2_width = max(col2_width, 3)

    sb = io.StringIO()

    # Header row
    sb.write(f"| {header_left:<{col1_width}} | {header_right:<{col2_width}} |\n")

    # Divider row
    sb.write(f"|{'-' * (col1_width + 2)}|{'-' * (col2_width + 2)}|\n")

    # Data rows
    for key, value in expanded:
        sb.write(f"| {key:<{col1_width}} | {value:<{col2_width}} |\n")

    return sb.getvalue()


def _word_wrap(text: str, width: int) -> list[str]:
    """Wrap text at word boundaries, appending '-' to broken lines like original."""
    lines = []
    while len(text) > width:
        # Find break point
        break_at = width
        for ch in (" ", "-", "\t"):
            pos = text.rfind(ch, 0, width)
            if pos > 0:
                break_at = pos + 1
                break

        line = text[:break_at].rstrip()
        lines.append(line + "-")
        text = text[break_at:].lstrip()

    if text:
        lines.append(text)
    return lines if lines else [text]
