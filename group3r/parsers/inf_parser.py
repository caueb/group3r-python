"""Parser for GptTmpl.inf security policy files."""

from __future__ import annotations

import logging
import re

from ..models.enums import RegHive, RegKeyValType, SettingAction
from ..models.settings import (
    EventAuditSetting, FileSecuritySetting, GpoSetting, GroupSetting,
    GroupSettingMember, KerbPolicySetting, NtServiceSetting,
    PrivRightSetting, RegistrySetting, RegistryValue,
    SystemAccessSetting,
)
from ..models.trustees import Trustee

logger = logging.getLogger(__name__)

_HEADING_RE = re.compile(r"^\[(\w+\s?)+\]$")


def parse_inf_file(filepath: str, content: bytes | None = None) -> list[GpoSetting]:
    """Parse a GptTmpl.inf file and return a list of GpoSettings."""
    settings: list[GpoSetting] = []

    if content is not None:
        # Decode bytes content, trying common encodings
        for enc in ("utf-8-sig", "utf-16-le", "latin-1"):
            try:
                text = content.decode(enc)
                raw_lines = text.splitlines(keepends=True)
                break
            except (UnicodeDecodeError, ValueError):
                continue
        else:
            logger.error("Failed to decode inf content for %s", filepath)
            return settings
    else:
        try:
            with open(filepath, "r", encoding="utf-8-sig") as f:
                raw_lines = f.readlines()
        except Exception:
            try:
                with open(filepath, "r", encoding="utf-16-le") as f:
                    raw_lines = f.readlines()
            except Exception as e:
                logger.error("Failed to read inf file %s: %s", filepath, e)
                return settings

    # Strip comment lines (starting with ;)
    lines = [line.rstrip("\n\r") for line in raw_lines if not line.strip().startswith(";")]
    content = "\n".join(lines)
    if not content.strip():
        return settings

    # Find heading line numbers
    heading_indices = [i for i, line in enumerate(lines) if _HEADING_RE.match(line.strip())]

    if not heading_indices:
        return settings

    # Build section slices: {start_line: end_line}
    sections: list[tuple[int, int]] = []
    for idx, start in enumerate(heading_indices):
        if idx + 1 < len(heading_indices):
            end = heading_indices[idx + 1] - 1
        else:
            end = len(lines) - 1
        sections.append((start, end))

    for start, end in sections:
        heading = lines[start].strip().strip("[]")
        section_lines = lines[start + 1: end + 1]

        for line in section_lines:
            line = line.strip()
            if not line:
                continue

            try:
                _parse_inf_line(heading, line, filepath, settings)
            except Exception as e:
                logger.debug("Error parsing line in %s [%s]: %s", filepath, heading, e)

    return settings


def _parse_inf_line(heading: str, line: str, filepath: str, settings: list[GpoSetting]) -> None:
    """Parse a single line within a section of an inf file."""
    line_key = ""
    split_values = None

    if "=" in line:
        parts = line.split("=", 1)
        line_key = parts[0].strip().strip('\\"')
        line_values = parts[1].strip()
        split_values = [v.strip() for v in line_values.split(",")]
    else:
        parts = line.split(",")
        line_key = parts[0].strip()

    if heading == "Privilege Rights":
        setting = PrivRightSetting(source=filepath, privilege=line_key)
        if split_values:
            for trustee_sid in split_values:
                trustee_sid = trustee_sid.strip()
                if not trustee_sid:
                    continue
                sid_str = trustee_sid.lstrip("*")
                t = Trustee(sid=sid_str if sid_str.startswith("S-") else "",
                            display_name="" if sid_str.startswith("S-") else sid_str)
                t.resolve_display_name()
                setting.trustees.append(t)
        if setting.trustees:
            settings.append(setting)

    elif heading == "Registry Values":
        setting = RegistrySetting(source=filepath)
        reg_path_parts = line_key.split("\\")
        # First part is hive shortname
        hive_map = {"MACHINE": RegHive.HKEY_LOCAL_MACHINE, "USER": RegHive.HKEY_CURRENT_USER}
        hive_str = reg_path_parts[0].strip('"')
        setting.hive = hive_map.get(hive_str, RegHive.HKEY_LOCAL_MACHINE)
        # Key is everything except first and last (last is value name)
        setting.key = "\\".join(reg_path_parts[1:-1])

        if split_values:
            try:
                val_type = int(split_values[0])
                for value_str in split_values[1:]:
                    reg_val = RegistryValue(
                        value_name=reg_path_parts[-1],
                        reg_key_val_type=RegKeyValType(val_type),
                        value_string=value_str,
                        value_bytes=value_str.encode("utf-16-le"),
                    )
                    setting.values.append(reg_val)
            except (ValueError, IndexError):
                pass
        settings.append(setting)

    elif heading == "Registry Keys":
        setting = RegistrySetting(source=filepath)
        # line format: "MACHINE\path\to\key",inheritance,"SDDL"
        full_parts = line.split(",")
        key_part = full_parts[0].strip().strip('"')
        reg_key_parts = key_part.split("\\")
        hive_str = reg_key_parts[0].strip('"')
        hive_map = {"MACHINE": RegHive.HKEY_LOCAL_MACHINE, "USER": RegHive.HKEY_CURRENT_USER}
        setting.hive = hive_map.get(hive_str, RegHive.HKEY_LOCAL_MACHINE)
        setting.key = "\\".join(reg_key_parts[1:]).strip('"')
        if len(full_parts) > 1:
            setting.inheritance = full_parts[1].strip()
        if len(full_parts) > 2:
            sddl_str = full_parts[2].strip().strip('"')
            if sddl_str:
                setting.key_sddl_string = sddl_str
        settings.append(setting)

    elif heading == "Kerberos Policy":
        full_parts = line.split("=", 1)
        if len(full_parts) == 2:
            setting = KerbPolicySetting(
                source=filepath,
                key=full_parts[0].strip(),
                value=full_parts[1].strip(),
            )
            settings.append(setting)

    elif heading == "Event Audit":
        setting = EventAuditSetting(source=filepath, audit_type=line_key)
        if split_values:
            try:
                setting.audit_level = int(split_values[0])
            except ValueError:
                pass
        settings.append(setting)

    elif heading == "File Security " or heading == "File Security":
        full_parts = line.split(",")
        if len(full_parts) >= 2:
            setting = FileSecuritySetting(
                source=filepath,
                file_sec_path=full_parts[0].strip(),
                sddl=full_parts[1].strip(),
            )
            settings.append(setting)

    elif heading == "Group Membership":
        if line_key.endswith("Memberof"):
            member = line_key.split("_")[0].strip("*")
            groups = split_values or []
            gsm = GroupSettingMember()
            if member.startswith("S-"):
                gsm.sid = member
                t = Trustee(sid=member)
                gsm.name = t.resolve_display_name()
            else:
                gsm.name = member

            for group in groups:
                group = group.strip()
                if not group:
                    continue
                group_clean = group.strip("*")
                t = Trustee(
                    sid=group_clean if group_clean.startswith("S-") else "",
                    display_name="" if group_clean.startswith("S-") else group_clean,
                )
                group_name = t.resolve_display_name()
                gs = GroupSetting(
                    source=filepath,
                    action=SettingAction.UPDATE,
                    name=group_name,
                )
                gs.members.append(GroupSettingMember(
                    name=gsm.name, sid=gsm.sid, action=gsm.action))
                settings.append(gs)

        elif line_key.endswith("Members"):
            group = line_key.split("_")[0].strip("*")
            members = split_values or []

            gs = GroupSetting(source=filepath, action=SettingAction.UPDATE)
            if group.startswith("S-"):
                t = Trustee(sid=group)
                gs.name = t.resolve_display_name()
            else:
                gs.name = group

            for member in members:
                member = member.strip()
                if not member:
                    continue
                trimmed = member.strip("*")
                gsm = GroupSettingMember()
                if trimmed.startswith("S-"):
                    gsm.sid = trimmed
                    t = Trustee(sid=trimmed)
                    gsm.name = t.resolve_display_name()
                else:
                    gsm.name = trimmed
                gs.members.append(gsm)

            if gs.members:
                settings.append(gs)

    elif heading == "Service General Setting":
        full_parts = line.split(",")
        setting = NtServiceSetting(source=filepath, service_name=line_key)
        if len(full_parts) > 1:
            setting.startup_type = full_parts[1].strip()
        if len(full_parts) > 2:
            sddl_str = full_parts[2].strip().strip('"')
            if sddl_str:
                setting.sddl = sddl_str
        settings.append(setting)

    elif heading == "System Access":
        full_parts = line.split("=", 1)
        if len(full_parts) == 2:
            setting = SystemAccessSetting(
                source=filepath,
                setting_name=full_parts[0].strip(),
                value_string=full_parts[1].strip(),
            )
            settings.append(setting)

    elif heading in ("Unicode", "Version"):
        pass  # Expected, not interesting

    else:
        logger.debug("Unhandled inf section: %s", heading)
