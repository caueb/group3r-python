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
            root = ET.fromstring(content)
        else:
            tree = ET.parse(filepath)
            root = tree.getroot()
    except ET.ParseError as e:
        logger.error("Failed to parse XML file %s: %s", filepath, e)
        return settings

    tag = root.tag

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
    for group in root.findall("Group"):
        gs = GroupSetting(source=filepath)
        gs.name = _attr(group, "name")
        props = group.find("Properties")
        gs.new_name = _attr(props, "newName")
        gs.action = parse_setting_action(_attr(props, "action"))
        gs.delete_all_groups = _parse_bool(_attr(props, "deleteAllGroups"))
        gs.delete_all_users = _parse_bool(_attr(props, "deleteAllUsers"))
        gs.remove_accounts = _parse_bool(_attr(props, "removeAccounts"))
        gs.description = _attr(props, "description")
        gs.group_sid = _attr(props, "groupSid")

        members_elem = props.find("Members") if props is not None else None
        if members_elem is not None:
            for member in members_elem:
                gsm = GroupSettingMember(
                    action=parse_setting_action(_attr(member, "action")),
                    name=_attr(member, "name"),
                    sid=_attr(member, "sid"),
                )
                gs.members.append(gsm)
        settings.append(gs)

    for user in root.findall("User"):
        us = UserSetting(source=filepath)
        us.name = _attr(user, "name")
        props = user.find("Properties")
        us.new_name = _attr(props, "newName")
        us.action = parse_setting_action(_attr(props, "action"))
        us.full_name = _attr(props, "fullName")
        us.cpassword = _attr(props, "cpassword")
        us.password = us.decrypt_cpassword(us.cpassword) or ""
        us.description = _attr(props, "description")
        us.user_name = _attr(props, "userName")
        us.account_disabled = _parse_bool(_attr(props, "acctDisabled"))
        us.pw_never_expires = _parse_bool(_attr(props, "neverExpires"))
        settings.append(us)


def _parse_data_sources(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ds in root.findall("DataSource"):
        dss = DataSourceSetting(source=filepath)
        dss.name = _attr(ds, "name")
        props = ds.find("Properties")
        dss.action = parse_setting_action(_attr(props, "action"))
        dss.dsn = _attr(props, "dsn")
        dss.cpassword = _attr(props, "cpassword")
        dss.password = dss.decrypt_cpassword(dss.cpassword) or ""
        dss.description = _attr(props, "description")
        dss.driver = _attr(props, "driver")
        dss.user_name = _attr(props, "username")
        settings.append(dss)


def _parse_drives(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for drive in root.findall("Drive"):
        ds = DriveSetting(source=filepath)
        ds.name = _attr(drive, "name")
        props = drive.find("Properties")
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
        settings.append(ds)


def _parse_env_vars(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ev in root.findall("EnvironmentVariable"):
        evs = EnvVarSetting(source=filepath)
        evs.name = _attr(ev, "name")
        evs.status = _attr(ev, "status")
        props = ev.find("Properties")
        evs.action = parse_setting_action(_attr(props, "action"))
        settings.append(evs)


def _parse_files(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for file_node in root.findall("File"):
        fs = FileSetting(source=filepath)
        fs.file_name = _attr(file_node, "name")
        fs.status = _attr(file_node, "status")
        props = file_node.find("Properties")
        fs.action = parse_setting_action(_attr(props, "action"))
        fs.from_path = _attr(props, "fromPath")
        fs.target_path = _attr(props, "targetPath")
        settings.append(fs)


def _parse_ini_files(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ini in root.findall("Ini"):
        ifs = IniFileSetting(source=filepath)
        props = ini.find("Properties")
        ifs.path = _attr(props, "path")
        ifs.section = _attr(props, "section")
        ifs.value = _attr(props, "value")
        ifs.property = _attr(props, "property")
        ifs.action = parse_setting_action(_attr(props, "action"))
        settings.append(ifs)


def _parse_network_options(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for _no in root.findall("NetworkOption"):
        nos = NetOptionSetting(source=filepath)
        settings.append(nos)
    logger.debug("NetworkOptions XML parsing is minimal")


def _parse_network_shares(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for ns in root.findall("NetworkShare"):
        nss = NetworkShareSetting(source=filepath)
        nss.name = _attr(ns, "name")
        props = ns.find("Properties")
        nss.action = parse_setting_action(_attr(props, "action"))
        nss.comment = _attr(props, "comment")
        nss.path = _attr(props, "path")
        nss.all_regular = _attr(props, "allRegular")
        nss.all_hidden = _attr(props, "allHidden")
        nss.all_admin_drive = _attr(props, "allAdminDrive")
        nss.limit_users = _attr(props, "limitUsers")
        nss.abe = _attr(props, "abe")
        settings.append(nss)


def _parse_nt_services(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for svc in root.findall("NTService"):
        ss = NtServiceSetting(source=filepath)
        ss.name = _attr(svc, "name")
        props = svc.find("Properties")
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
        settings.append(ss)


def _parse_printers(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for printer in root.findall("SharedPrinter"):
        ps = PrinterSetting(source=filepath)
        ps.name = _attr(printer, "name")
        props = printer.find("Properties")
        ps.user_name = _attr(props, "userName")
        ps.cpassword = _attr(props, "cpassword")
        ps.password = ps.decrypt_cpassword(ps.cpassword) or ""
        ps.action = parse_setting_action(_attr(props, "action"))
        ps.path = _attr(props, "path")
        ps.port = _attr(props, "port")
        ps.comment = _attr(props, "comment")
        settings.append(ps)


def _parse_shortcuts(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for sc in root.findall("Shortcut"):
        ss = ShortcutSetting(source=filepath)
        ss.name = _attr(sc, "name")
        ss.status = _attr(sc, "status")
        props = sc.find("Properties")
        ss.target_type = _attr(props, "targetType")
        ss.target_path = _attr(props, "targetPath")
        ss.arguments = _attr(sc, "arguments")
        ss.comment = _attr(props, "comment")
        ss.shortcut_path = _attr(props, "shortcutPath")
        ss.icon_path = _attr(props, "iconPath")
        ss.icon_index = _attr(props, "iconIndex")
        ss.start_in = _attr(props, "startIn")
        ss.action = parse_setting_action(_attr(props, "action"))
        settings.append(ss)


def _parse_registry_settings(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for rs_node in root.iter("Registry"):
        rs = RegistrySetting(source=filepath)
        rs.name = _attr(rs_node, "name")
        rs.status = _attr(rs_node, "status")
        rs.changed = _parse_datetime(_attr(rs_node, "changed"))
        rs.display_decimal = _attr(rs_node, "displayDecimal")

        props = rs_node.find("Properties")
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
        settings.append(rs)


def _parse_devices(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for device in root.findall("Device"):
        ds = DeviceSetting(source=filepath)
        ds.name = _attr(device, "name")
        props = device.find("Properties")
        ds.device_class = _attr(props, "deviceClass")
        ds.device_action = _attr(props, "deviceAction")
        ds.device_class_guid = _attr(props, "deviceClassGUID")
        ds.device_type = _attr(props, "deviceType")
        ds.device_type_id = _attr(props, "deviceTypeID")
        settings.append(ds)


def _parse_folders(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for folder in root.findall("Folder"):
        fs = FolderSetting(source=filepath)
        fs.name = _attr(folder, "name")
        fs.status = _attr(folder, "status")
        props = folder.find("Properties")
        fs.action = parse_setting_action(_attr(props, "action"))
        fs.path = _attr(props, "path")
        settings.append(fs)


# --- Scheduled Task Parsing ---

def _xml_text(node: Optional[ET.Element], xpath: str) -> str:
    """Safely get text from an XPath query."""
    if node is None:
        return ""
    elem = node.find(xpath)
    return elem.text if elem is not None and elem.text else ""


def _parse_sched_task_v1(task_type: SchedTaskType, node: ET.Element, filepath: str) -> SchedTaskSetting:
    """Parse a v1 Task or ImmediateTask element."""
    sts = SchedTaskSetting(source=filepath, task_type=task_type)
    sts.name = _attr(node, "name")
    sts.changed = _parse_datetime(_attr(node, "changed"))

    props = node.find("Properties")
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

    props = node.find("Properties")
    sts.setting_action = parse_setting_action(_attr(props, "action"))

    # Registration Info
    reg_info = props.find("Task/RegistrationInfo") if props is not None else None
    sts.author = _xml_text(reg_info, "Author")
    sts.description1 = _xml_text(reg_info, "Description")

    # Principals
    sts.principals = []
    principals_nodes = props.findall("Task/Principals/Principal") if props is not None else []
    for p in principals_nodes:
        principal = SchedTaskPrincipal(
            id=_attr(p, "id"),
            user_id=_xml_text(p, "UserId"),
            logon_type=_xml_text(p, "LogonType"),
            run_level=_xml_text(p, "RunLevel"),
            cpassword=_xml_text(p, "Cpassword"),
        )
        sts.principals.append(principal)

    # Settings
    sts.duration = _xml_text(props, "Task/Settings/IdleSettings/Duration")
    sts.wait_timeout = _xml_text(props, "Task/Settings/IdleSettings/WaitTimeout")
    sts.stop_on_idle_end = _parse_bool(_xml_text(props, "Task/Settings/IdleSettings/StopOnIdleEnd"))
    sts.restart_on_idle = _parse_bool(_xml_text(props, "Task/Settings/IdleSettings/RestartOnIdle"))
    sts.multiple_instances_policy = _xml_text(props, "Task/Settings/MultipleInstancesPolicy")
    sts.disallow_start_if_on_batteries = _parse_bool(
        _xml_text(props, "Task/Settings/DisallowStartIfOnBatteries"))
    sts.stop_if_going_on_batteries = _parse_bool(
        _xml_text(props, "Task/Settings/StopIfGoingOnBatteries"))
    sts.allow_hard_terminate = _parse_bool(_xml_text(props, "Task/Settings/AllowHardTerminate"))
    sts.allow_start_on_demand = _parse_bool(_xml_text(props, "Task/Settings/AllowStartOnDemand"))
    sts.enabled = _parse_bool(_xml_text(props, "Task/Settings/Enabled"))
    sts.hidden = _parse_bool(_xml_text(props, "Task/Settings/Hidden"))
    sts.execution_time_limit = _xml_text(props, "Task/Settings/ExecutionTimeLimit")

    priority_str = _xml_text(props, "Task/Settings/Priority")
    if priority_str:
        try:
            sts.priority = int(priority_str)
        except ValueError:
            pass

    # Actions
    actions = []
    if props is not None:
        for msg in props.findall("Task/Actions/ShowMessage"):
            actions.append(SchedTaskShowMessageAction(
                title=_xml_text(msg, "Title"),
                body=_xml_text(msg, "Body"),
            ))
        for exec_node in props.findall("Task/Actions/Exec"):
            actions.append(SchedTaskExecAction(
                command=_xml_text(exec_node, "Command"),
                args=_xml_text(exec_node, "Arguments"),
                working_dir=_xml_text(exec_node, "WorkingDirectory"),
            ))
        for email in props.findall("Task/Actions/SendEmail"):
            ea = SchedTaskEmailAction(
                from_addr=_xml_text(email, "From"),
                to=_xml_text(email, "To"),
                subject=_xml_text(email, "Subject"),
                body=_xml_text(email, "Body"),
                header_fields=_xml_text(email, "HeaderFields"),
                server=_xml_text(email, "Server"),
            )
            attachments_node = email.find("Attachments")
            if attachments_node is not None:
                ea.attachments = [a.text for a in attachments_node if a.text]
            actions.append(ea)
    sts.actions = actions

    sts.comment = _attr(props, "comment")
    sts.system_required = _parse_bool(_attr(props, "systemRequired"))

    return sts


def _parse_scheduled_tasks(root: ET.Element, filepath: str, settings: list[GpoSetting]) -> None:
    for task in root.findall("Task"):
        settings.append(_parse_sched_task_v1(SchedTaskType.TASK, task, filepath))
    for task in root.findall("TaskV2"):
        settings.append(_parse_sched_task_v2(SchedTaskType.TASK_V2, task, filepath))
    for task in root.findall("ImmediateTask"):
        settings.append(_parse_sched_task_v1(SchedTaskType.IMMEDIATE_TASK, task, filepath))
    for task in root.findall("ImmediateTaskV2"):
        settings.append(_parse_sched_task_v2(SchedTaskType.IMMEDIATE_TASK_V2, task, filepath))
