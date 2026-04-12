"""Parser for registry.pol binary files."""

from __future__ import annotations

import logging
import struct
from pathlib import PurePosixPath, PureWindowsPath

from ..models.enums import RegHive, RegKeyValType
from ..models.settings import GpoSetting, RegistrySetting, RegistryValue

logger = logging.getLogger(__name__)

# registry.pol file signature: "PReg"
_POL_SIGNATURE = 0x67655250


def parse_pol_file(filepath: str, content: bytes | None = None) -> list[GpoSetting]:
    """Parse a registry.pol binary file and return a list of RegistrySettings."""
    settings: list[GpoSetting] = []

    if content is None:
        with open(filepath, "rb") as f:
            content = f.read()
    data = content

    if len(data) < 8:
        logger.warning("registry.pol file too small: %s", filepath)
        return settings

    signature = struct.unpack_from("<I", data, 0)[0]
    if signature != _POL_SIGNATURE:
        logger.warning("Invalid registry.pol signature in %s", filepath)
        return settings

    # version = struct.unpack_from("<I", data, 4)[0]
    pos = 8
    filepath_lower = filepath.lower().replace("\\", "/")

    # Determine hive from path
    if "/machine/" in filepath_lower or "\\machine\\" in filepath_lower.replace("/", "\\"):
        hive = RegHive.HKEY_LOCAL_MACHINE
    elif "/user/" in filepath_lower or "\\user\\" in filepath_lower.replace("/", "\\"):
        hive = RegHive.HKEY_CURRENT_USER
    else:
        logger.warning("Cannot determine hive from path: %s", filepath)
        hive = RegHive.HKEY_LOCAL_MACHINE

    while pos < len(data):
        try:
            setting = RegistrySetting(source=filepath, hive=hive)

            # Read opening bracket '[' (UTF-16LE = 2 bytes)
            pos += 2

            # Read key path (null-terminated UTF-16LE)
            key_path, pos = _read_null_terminated_utf16(data, pos)
            # Skip the separator ';'
            pos += 2

            # Read value name
            value_name, pos = _read_null_terminated_utf16(data, pos)
            pos += 2  # separator

            # Read type (uint32)
            val_type = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            pos += 2  # separator

            # Read size (uint32)
            val_size = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            pos += 2  # separator

            # Read value bytes
            val_bytes = data[pos:pos + val_size]
            pos += val_size

            # Read closing bracket ']'
            pos += 2

            # Build the key (skip first component which is redundant)
            key_parts = key_path.split("\\")
            setting.key = "\\".join(key_parts[1:]) if len(key_parts) > 1 else key_path

            # Build registry value
            try:
                reg_val_type = RegKeyValType(val_type)
            except ValueError:
                reg_val_type = RegKeyValType.REG_NONE

            reg_val = RegistryValue(
                value_name=value_name,
                reg_key_val_type=reg_val_type,
                value_bytes=val_bytes,
            )

            # Convert value to string representation
            if reg_val_type == RegKeyValType.REG_DWORD and len(val_bytes) >= 4:
                reg_val.value_string = str(struct.unpack_from("<i", val_bytes, 0)[0])
            elif reg_val_type in (RegKeyValType.REG_SZ, RegKeyValType.REG_MULTI_SZ):
                try:
                    decoded = val_bytes.decode("utf-16-le")
                    reg_val.value_string = decoded.replace("\x00", " ")
                except Exception:
                    reg_val.value_string = val_bytes.hex()
            else:
                try:
                    reg_val.value_string = val_bytes.decode("utf-16-le")
                except Exception:
                    reg_val.value_string = val_bytes.hex()

            setting.values.append(reg_val)
            settings.append(setting)

        except (struct.error, IndexError) as e:
            logger.warning("Error parsing registry.pol at offset %d: %s", pos, e)
            break

    return settings


def _read_null_terminated_utf16(data: bytes, pos: int) -> tuple[str, int]:
    """Read a null-terminated UTF-16LE string from data at pos. Returns (string, new_pos)."""
    chars = []
    while pos + 1 < len(data):
        char_val = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if char_val == 0:
            break
        chars.append(chr(char_val))
    return "".join(chars), pos
