"""Parser for XML Group Policy Preferences files."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional
from xml.etree import ElementTree as ET

from ..models.enums import (
    RegHive, RegKeyValType, SchedTaskType, SettingAction, parse_setting_action,
)
from ..models.settings import (
    DataSourceSetting, DeviceSetting, DriveSetting, EnvVarSetting,
    FileSetting, FolderSetting, GpoSetting, GroupSetting,
    GroupSettingMember, IniFileSetting, NetOptionSetting,
    NetworkShareSetting, NtServiceSetting, PrinterSetting,
    RegistrySetting, RegistryValue, SchedTaskExecAction,
    SchedTaskEmailAction, SchedTaskPrincipal, SchedTaskSetting,
    SchedTaskShowMessageAction, ShortcutSetting, UserSetting,
)

logger = logging.getLogger(__name__)


def _local_tag(tag: str) -> str:
    """Strip an XML namespace so GPP TaskV2 xmlns does not hide elements."""
    if tag and tag.startswith("{"):
        return tag.split("}", 1)[-1]
    return tag or ""


def _children(elem: Optional[ET.Element], name: str) -> list[ET.Element]:
    if elem is None:
        return []
    return [c for c in list(elem) if _local_tag(c.tag) == name]


def _find_child(elem: Optional[ET.Element], name: str) -> Optional[ET.Element]:
    kids = _children(elem, name)
    return kids[0] if kids else None


def _descendants(elem: Optional[ET.Element], name: str) -> list[ET.Element]:
    """All nested elements with this local name (GPP Collection wrappers)."""
    if elem is None:
        return []
    return [e for e in elem.iter() if e is not elem and _local_tag(e.tag) == name]


def _gpp_items(root: ET.Element, name: str) -> list[ET.Element]:
    """GPP items: direct children of root or of a Collection wrapper.

    Do not recurse into Properties (TaskV2 embeds an inner <Task>).
    """
    items = _children(root, name)
    for coll in _children(root, "Collection"):
        items.extend(_gpp_items(coll, name))
    return items


def _add_setting(settings: list[GpoSetting], setting: GpoSetting,
                 node: Optional[ET.Element] = None) -> None:
    if node is not None and (_find_child(node, "Filters") or _descendants(node, "Filter")):
        setting.has_filters = True
    settings.append(setting)


def _find_path(elem: Optional[ET.Element], *names: str) -> Optional[ET.Element]:
    cur = elem
    for name in names:
        cur = _find_child(cur, name)
        if cur is None:
            return None
    return cur


def _findall_path(elem: Optional[ET.Element], *names: str) -> list[ET.Element]:
    nodes = [elem] if elem is not None else []
    for name in names:
        next_nodes: list[ET.Element] = []
        for node in nodes:
            next_nodes.extend(_children(node, name))
        nodes = next_nodes
    return nodes


def _attr(elem: Optional[ET.Element], name: str) -> str:
    """Safely get an attribute value, returning empty string if missing."""
    if elem is None:
        return ""
    return elem.get(name, "") or ""


def _parse_bool(value: str) -> bool:
    """Parse a boolean string value."""
    return value.lower() in ("true", "1") if value else False


def _parse_datetime(value: str) -> Optional[datetime]:
    """Try to parse a datetime string."""
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_xml_file(filepath: str, content: bytes | None = None) -> list[GpoSetting]:
    """Parse an XML GPP file and return a list of GpoSettings."""
    settings: list[GpoSetting] = []

    try:
        if content is not None:
            if isinstance(content, bytes):
                from .util import decode_bytes
                text = decode_bytes(content)
                root = ET.fromstring(text)
            else:
                root = ET.fromstring(content)
        else:
            tree = ET.parse(filepath)
            root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse XML file %s: %s", filepath, e)
        return settings

    tag = _local_tag(root.tag)

    try:
        if tag == "Groups":
            _parse_groups(root, filepath, settings)
        elif tag == "DataSources":
            _parse_data_sources(root, filepath, settings)
        elif tag == "Drives":
            _parse_drives(root, filepath, settings)
        elif tag == "EnvironmentVariables":
            _parse_env_vars(root, filepath, settings)
        elif tag == "Files":
            _parse_files(root, filepath, settings)
        elif tag == "IniFiles":
            _parse_ini_files(root, filepath, settings)
        elif tag == "NetworkOptions":
            _parse_network_options(root, filepath, settings)
        elif tag == "NetworkShareSettings":
            _parse_network_shares(root, filepath, settings)
        elif tag == "NTServices":
            _parse_nt_services(root, filepath, settings)
        elif tag == "Printers":
            _parse_printers(root, filepath, settings)
        elif tag == "ScheduledTasks":
            _parse_scheduled_tasks(root, filepath, settings)
        elif tag == "Shortcuts":
            _parse_shortcuts(root, filepath, settings)
        elif tag == "RegistrySettings":
            _parse_registry_settings(root, filepath, settings)
        elif tag == "Devices":
            _parse_devices(root, filepath, settings)
        elif tag == "Folders":
            _parse_folders(root, filepath, settings)
        elif tag == "InternetSettings":
            logger.debug("InternetSettings XML parsing not implemented")
        else:
            logger.debug("No handler for XML root element: %s", tag)
    except Exception as e:
        logger.error("Error parsing XML file %s: %s", filepath, e)

    return settings


def _parse_groups(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for group in _descendants(root, "Group"):
        gs = GroupSetting(source=filepath)
        gs.name = _attr(group, "name")
        props = _find_child(group, "Properties")
        gs.new_name = _attr(props, "newName")
        gs.action = parse_setting_action(_attr(props, "action"))
        gs.delete_all_groups = _parse_bool(_attr(props, "deleteAllGroups"))
        gs.delete_all_users = _parse_bool(_attr(props, "deleteAllUsers"))
        gs.remove_accounts = _parse_bool(_attr(props, "removeAccounts"))
        gs.description = _attr(props, "description")
        gs.group_sid = _attr(props, "groupSid")

        members_elem = _find_child(props, "Members") if props is not None else None
        if members_elem is not None:
            for member in members_elem:
                gsm = GroupSettingMember(
                    action=parse_setting_action(_attr(member, "action")),
                    name=_attr(member, "name"),
                    sid=_attr(member, "sid"),
                )
                gs.members.append(gsm)
        _add_setting(settings, gs, group)

    for user in _descendants(root, "User"):
        us = UserSetting(source=filepath)
        us.name = _attr(user, "name")
        props = _find_child(user, "Properties")
        us.new_name = _attr(props, "newName")
        us.action = parse_setting_action(_attr(props, "action"))
        us.full_name = _attr(props, "fullName")
        us.cpassword = _attr(props, "cpassword")
        us.password = us.decrypt_cpassword(us.cpassword) or ""
        us.description = _attr(props, "description")
        us.user_name = _attr(props, "userName")
        us.account_disabled = _parse_bool(_attr(props, "acctDisabled"))
        us.pw_never_expires = _parse_bool(_attr(props, "neverExpires"))
        _add_setting(settings, us, user)


def _parse_data_sources(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ds in _descendants(root, "DataSource"):
        dss = DataSourceSetting(source=filepath)
        dss.name = _attr(ds, "name")
        props = _find_child(ds, "Properties")
        dss.action = parse_setting_action(_attr(props, "action"))
        dss.dsn = _attr(props, "dsn")
        dss.cpassword = _attr(props, "cpassword")
        dss.password = dss.decrypt_cpassword(dss.cpassword) or ""
        dss.description = _attr(props, "description")
        dss.driver = _attr(props, "driver")
        dss.user_name = _attr(props, "username")
        _add_setting(settings, dss, ds)


def _parse_drives(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for drive in _descendants(root, "Drive"):
        ds = DriveSetting(source=filepath)
        ds.name = _attr(drive, "name")
        props = _find_child(drive, "Properties")
        ds.action = parse_setting_action(_attr(props, "action"))
        ds.drive_letter = _attr(props, "useLetter")
        ds.this_drive = _attr(props, "thisDrive")
        ds.all_drives = _attr(props, "allDrives")
        ds.user_name = _attr(props, "userName")
        ds.cpassword = _attr(props, "cpassword")
        ds.password = ds.decrypt_cpassword(ds.cpassword) or ""
        ds.path = _attr(props, "path")
        ds.label = _attr(props, "label")
        ds.persistent = _attr(props, "persistent")
        ds.letter = _attr(props, "letter")
        _add_setting(settings, ds, drive)


def _parse_env_vars(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ev in _descendants(root, "EnvironmentVariable"):
        evs = EnvVarSetting(source=filepath)
        evs.name = _attr(ev, "name")
        evs.status = _attr(ev, "status")
        props = _find_child(ev, "Properties")
        evs.action = parse_setting_action(_attr(props, "action"))
        _add_setting(settings, evs, ev)


def _parse_files(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for file_node in _descendants(root, "File"):
        fs = FileSetting(source=filepath)
        fs.file_name = _attr(file_node, "name")
        fs.status = _attr(file_node, "status")
        props = _find_child(file_node, "Properties")
        fs.action = parse_setting_action(_attr(props, "action"))
        fs.from_path = _attr(props, "fromPath")
        fs.target_path = _attr(props, "targetPath")
        _add_setting(settings, fs, file_node)


def _parse_ini_files(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ini in _descendants(root, "Ini"):
        ifs = IniFileSetting(source=filepath)
        props = _find_child(ini, "Properties")
        ifs.path = _attr(props, "path")
        ifs.section = _attr(props, "section")
        ifs.value = _attr(props, "value")
        ifs.property = _attr(props, "property")
        ifs.action = parse_setting_action(_attr(props, "action"))
        _add_setting(settings, ifs, ini)


def _parse_network_options(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for node in _descendants(root, "DUN") + _descendants(root, "NetworkOption"):
        nos = NetOptionSetting(source=filepath)
        nos.name = _attr(node, "name")
        props = _find_child(node, "Properties")
        nos.action = parse_setting_action(_attr(props, "action"))
        nos.user_name = _attr(props, "user")
        nos.phone_number = _attr(props, "phoneNumber")
        nos.cpassword = _attr(props, "cpassword")
        _add_setting(settings, nos, node)


def _parse_network_shares(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ns in _descendants(root, "NetworkShare"):
        nss = NetworkShareSetting(source=filepath)
        nss.name = _attr(ns, "name")
        props = _find_child(ns, "Properties")
        nss.action = parse_setting_action(_attr(props, "action"))
        nss.comment = _attr(props, "comment")
        nss.path = _attr(props, "path")
        nss.all_regular = _attr(props, "allRegular")
        nss.all_hidden = _attr(props, "allHidden")
        nss.all_admin_drive = _attr(props, "allAdminDrive")
        nss.limit_users = _attr(props, "limitUsers")
        nss.abe = _attr(props, "abe")
        _add_setting(settings, nss, ns)


def _parse_nt_services(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for svc in _descendants(root, "NTService"):
        ss = NtServiceSetting(source=filepath)
        ss.name = _attr(svc, "name")
        props = _find_child(svc, "Properties")
        ss.service_name = _attr(props, "serviceName")
        ss.service_action = _attr(props, "serviceAction")
        ss.timeout = _attr(props, "timeout")
        ss.program = _attr(props, "program")
        ss.args = _attr(props, "arguments")
        ss.startup_type = _attr(props, "startupType")
        ss.account_name = _attr(props, "accountName")
        ss.user_name = _attr(props, "userName")
        ss.cpassword = _attr(props, "cpassword")
        ss.password = ss.decrypt_cpassword(ss.cpassword) or ""
        ss.action_on_first_failure = _attr(props, "firstFailure")
        ss.reset_fail_count_delay = _attr(props, "resetFailCountDelay")
        ss.append = _attr(props, "append")
        ss.interact = _attr(props, "interact")
        _add_setting(settings, ss, svc)


def _parse_printers(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for printer in (
        _descendants(root, "SharedPrinter")
        + _descendants(root, "PortPrinter")
        + _descendants(root, "LocalPrinter")
    ):
        ps = PrinterSetting(source=filepath)
        ps.name = _attr(printer, "name")
        props = _find_child(printer, "Properties")
        ps.user_name = _attr(props, "userName")
        ps.cpassword = _attr(props, "cpassword")
        ps.password = ps.decrypt_cpassword(ps.cpassword) or ""
        ps.action = parse_setting_action(_attr(props, "action"))
        ps.path = _attr(props, "path")
        ps.port = _attr(props, "port")
        ps.comment = _attr(props, "comment")
        _add_setting(settings, ps, printer)


def _parse_shortcuts(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for sc in _descendants(root, "Shortcut"):
        ss = ShortcutSetting(source=filepath)
        ss.name = _attr(sc, "name")
        ss.status = _attr(sc, "status")
        props = _find_child(sc, "Properties")
        ss.target_type = _attr(props, "targetType")
        ss.target_path = _attr(props, "targetPath")
        ss.arguments = _attr(props, "arguments") or _attr(sc, "arguments")
        ss.comment = _attr(props, "comment")
        ss.shortcut_path = _attr(props, "shortcutPath")
        ss.icon_path = _attr(props, "iconPath")
        ss.icon_index = _attr(props, "iconIndex")
        ss.start_in = _attr(props, "startIn")
        ss.action = parse_setting_action(_attr(props, "action"))
        _add_setting(settings, ss, sc)


def _parse_registry_settings(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for rs_node in _descendants(root, "Registry"):
        rs = RegistrySetting(source=filepath)
        rs.name = _attr(rs_node, "name")
        rs.status = _attr(rs_node, "status")
        rs.changed = _parse_datetime(_attr(rs_node, "changed"))
        rs.display_decimal = _attr(rs_node, "displayDecimal")

        props = _find_child(rs_node, "Properties")
        rs.action = parse_setting_action(_attr(props, "action"))
        rs.default = _attr(props, "default")

        # Parse hive
        hive_str = _attr(props, "hive")
        try:
            rs.hive = RegHive(hive_str)
        except ValueError:
            rs.hive = RegHive.HKEY_LOCAL_MACHINE

        rs.key = _attr(props, "key")

        # Parse value
        reg_val = RegistryValue(value_name=_attr(props, "name"))
        type_str = _attr(props, "type")
        try:
            reg_val.reg_key_val_type = RegKeyValType[type_str] if type_str else RegKeyValType.REG_NONE
        except KeyError:
            reg_val.reg_key_val_type = RegKeyValType.REG_NONE

        val_str = _attr(props, "value")
        reg_val.value_string = val_str
        reg_val.value_bytes = val_str.encode("utf-16-le") if val_str else b""
        rs.values.append(reg_val)
        _add_setting(settings, rs, rs_node)


def _parse_devices(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for device in _descendants(root, "Device"):
        ds = DeviceSetting(source=filepath)
        ds.name = _attr(device, "name")
        props = _find_child(device, "Properties")
        ds.device_class = _attr(props, "deviceClass")
        ds.device_action = _attr(props, "deviceAction")
        ds.device_class_guid = _attr(props, "deviceClassGUID")
        ds.device_type = _attr(props, "deviceType")
        ds.device_type_id = _attr(props, "deviceTypeID")
        _add_setting(settings, ds, device)


def _parse_folders(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for folder in _descendants(root, "Folder"):
        fs = FolderSetting(source=filepath)
        fs.name = _attr(folder, "name")
        fs.status = _attr(folder, "status")
        props = _find_child(folder, "Properties")
        fs.action = parse_setting_action(_attr(props, "action"))
        fs.path = _attr(props, "path")
        _add_setting(settings, fs, folder)


# --- Scheduled Task Parsing ---

def _child_text(node: Optional[ET.Element], name: str) -> str:
    """Text of a direct child, ignoring XML namespaces."""
    child = _find_child(node, name)
    return child.text if child is not None and child.text else ""


def _path_text(node: Optional[ET.Element], *names: str) -> str:
    found = _find_path(node, *names)
    return found.text if found is not None and found.text else ""


def _parse_sched_task_v1(task_type: SchedTaskType, node: ET.Element, filepath: str) -> SchedTaskSetting:
    """Parse a v1 Task or ImmediateTask element."""
    sts = SchedTaskSetting(source=filepath, task_type=task_type)
    sts.name = _attr(node, "name")
    sts.changed = _parse_datetime(_attr(node, "changed"))

    props = _find_child(node, "Properties")
    sts.setting_action = parse_setting_action(_attr(props, "action"))

    action = SchedTaskExecAction(
        command=_attr(props, "appName"),
        args=_attr(props, "args"),
        working_dir=_attr(props, "startIn"),
    )
    sts.actions = [action]
    sts.comment = _attr(props, "comment")
    sts.disallow_start_if_on_batteries = _parse_bool(_attr(props, "noStartIfOnBatteries"))
    sts.start_only_if_idle = _parse_bool(_attr(props, "startOnlyIfIdle"))
    sts.stop_on_idle_end = _parse_bool(_attr(props, "stopOnIdleEnd"))
    sts.stop_if_going_on_batteries = _parse_bool(_attr(props, "stopIfGoingOnBatteries"))
    sts.system_required = _parse_bool(_attr(props, "systemRequired"))

    principal = SchedTaskPrincipal(
        user_id=_attr(props, "runAs"),
        logon_type=_attr(props, "logonType"),
        cpassword=_attr(props, "cpassword"),
    )
    sts.principals = [principal]
    sts.enabled = _parse_bool(_attr(props, "enabled"))

    return sts


def _parse_sched_task_v2(task_type: SchedTaskType, node: ET.Element, filepath: str) -> SchedTaskSetting:
    """Parse a v2 TaskV2 or ImmediateTaskV2 element."""
    sts = SchedTaskSetting(source=filepath, task_type=task_type)
    sts.name = _attr(node, "name")
    sts.changed = _parse_datetime(_attr(node, "changed"))

    props = _find_child(node, "Properties")
    sts.setting_action = parse_setting_action(_attr(props, "action"))

    task_node = _find_child(props, "Task")
    reg_info = _find_child(task_node, "RegistrationInfo")
    sts.author = _child_text(reg_info, "Author")
    sts.description1 = _child_text(reg_info, "Description")

    # Principals. GPP often puts cpassword/runAs on Properties, not Principal.
    props_cpassword = _attr(props, "cpassword")
    props_runas = _attr(props, "runAs")
    sts.principals = []
    principals_nodes = _findall_path(task_node, "Principals", "Principal")
    for p in principals_nodes:
        principal = SchedTaskPrincipal(
            id=_attr(p, "id"),
            user_id=_child_text(p, "UserId") or props_runas,
            logon_type=_child_text(p, "LogonType") or _attr(props, "logonType"),
            run_level=_child_text(p, "RunLevel"),
            cpassword=_child_text(p, "Cpassword") or props_cpassword,
        )
        sts.principals.append(principal)
    if not sts.principals and (props_cpassword or props_runas):
        sts.principals.append(SchedTaskPrincipal(
            user_id=props_runas,
            logon_type=_attr(props, "logonType"),
            cpassword=props_cpassword,
        ))

    idle = _find_path(task_node, "Settings", "IdleSettings")
    settings_node = _find_child(task_node, "Settings")
    sts.duration = _child_text(idle, "Duration")
    sts.wait_timeout = _child_text(idle, "WaitTimeout")
    sts.stop_on_idle_end = _parse_bool(_child_text(idle, "StopOnIdleEnd"))
    sts.restart_on_idle = _parse_bool(_child_text(idle, "RestartOnIdle"))
    sts.multiple_instances_policy = _child_text(settings_node, "MultipleInstancesPolicy")
    sts.disallow_start_if_on_batteries = _parse_bool(
        _child_text(settings_node, "DisallowStartIfOnBatteries"))
    sts.stop_if_going_on_batteries = _parse_bool(
        _child_text(settings_node, "StopIfGoingOnBatteries"))
    sts.allow_hard_terminate = _parse_bool(_child_text(settings_node, "AllowHardTerminate"))
    sts.allow_start_on_demand = _parse_bool(_child_text(settings_node, "AllowStartOnDemand"))
    sts.enabled = _parse_bool(_child_text(settings_node, "Enabled"))
    sts.hidden = _parse_bool(_child_text(settings_node, "Hidden"))
    sts.execution_time_limit = _child_text(settings_node, "ExecutionTimeLimit")

    priority_str = _child_text(settings_node, "Priority")
    if priority_str:
        try:
            sts.priority = int(priority_str)
        except ValueError:
            pass

    actions = []
    for msg in _findall_path(task_node, "Actions", "ShowMessage"):
        actions.append(SchedTaskShowMessageAction(
            title=_child_text(msg, "Title"),
            body=_child_text(msg, "Body"),
        ))
    for exec_node in _findall_path(task_node, "Actions", "Exec"):
        actions.append(SchedTaskExecAction(
            command=_child_text(exec_node, "Command"),
            args=_child_text(exec_node, "Arguments"),
            working_dir=_child_text(exec_node, "WorkingDirectory"),
        ))
    for email in _findall_path(task_node, "Actions", "SendEmail"):
        ea = SchedTaskEmailAction(
            from_addr=_child_text(email, "From"),
            to=_child_text(email, "To"),
            subject=_child_text(email, "Subject"),
            body=_child_text(email, "Body"),
            header_fields=_child_text(email, "HeaderFields"),
            server=_child_text(email, "Server"),
        )
        attachments_node = _find_child(email, "Attachments")
        if attachments_node is not None:
            ea.attachments = [a.text for a in attachments_node if a.text]
        actions.append(ea)
    sts.actions = actions

    sts.comment = _attr(props, "comment")
    sts.system_required = _parse_bool(_attr(props, "systemRequired"))

    return sts


def _parse_scheduled_tasks(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for task in _gpp_items(root, "Task"):
        _add_setting(settings, _parse_sched_task_v1(SchedTaskType.TASK, task, filepath), task)
    for task in _gpp_items(root, "TaskV2"):
        _add_setting(settings, _parse_sched_task_v2(SchedTaskType.TASK_V2, task, filepath), task)
    for task in _gpp_items(root, "ImmediateTask"):
        _add_setting(settings, _parse_sched_task_v1(SchedTaskType.IMMEDIATE_TASK, task, filepath), task)
    for task in _gpp_items(root, "ImmediateTaskV2"):
        _add_setting(settings, _parse_sched_task_v2(SchedTaskType.IMMEDIATE_TASK_V2, task, filepath), task)
