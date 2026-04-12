"""Parser for scripts.ini and psscripts.ini files."""

from __future__ import annotations

import logging
import re

from ..models.enums import ScriptType
from ..models.settings import GpoSetting, ScriptSetting

logger = logging.getLogger(__name__)

_HEADING_RE = re.compile(r"^\[(\w+\s?)+\]$")

_SCRIPT_TYPE_MAP = {
    "Startup": ScriptType.STARTUP,
    "Shutdown": ScriptType.SHUTDOWN,
    "Logon": ScriptType.LOGON,
    "Logoff": ScriptType.LOGOFF,
}


def parse_ini_file(filepath: str, content: bytes | None = None) -> list[GpoSetting]:
    """Parse a scripts.ini or psscripts.ini file and return ScriptSettings."""
    settings: list[GpoSetting] = []

    if content is not None:
        for enc in ("utf-8-sig", "utf-16-le", "latin-1"):
            try:
                text = content.decode(enc)
                lines = [line.rstrip("\n\r") for line in text.splitlines()]
                break
            except (UnicodeDecodeError, ValueError):
                continue
        else:
            logger.error("Failed to decode ini content for %s", filepath)
            return settings
    else:
        try:
            with open(filepath, "r", encoding="utf-8-sig") as f:
                lines = [line.rstrip("\n\r") for line in f.readlines()]
        except Exception:
            try:
                with open(filepath, "r", encoding="utf-16-le") as f:
                    lines = [line.rstrip("\n\r") for line in f.readlines()]
            except Exception as e:
                logger.error("Failed to read ini file %s: %s", filepath, e)
                return settings

    content = "\n".join(lines)
    if not content.strip():
        return settings

    # Find heading lines
    heading_indices = [i for i, line in enumerate(lines) if _HEADING_RE.match(line.strip())]
    if not heading_indices:
        return settings

    # Build section slices
    sections: list[tuple[int, int]] = []
    for idx, start in enumerate(heading_indices):
        if idx + 1 < len(heading_indices):
            end = heading_indices[idx + 1] - 1
        else:
            end = len(lines) - 1
        sections.append((start, end))

    for start, end in sections:
        heading = lines[start].strip().strip("[]")
        script_type = _SCRIPT_TYPE_MAP.get(heading)
        if script_type is None:
            logger.debug("Unknown script section heading: %s", heading)
            continue

        section_lines = lines[start + 1: end + 1]

        # Group lines by subsection index (the leading digit)
        lines_dict: dict[int, list[str]] = {}
        for line in section_lines:
            line = line.strip()
            if not line:
                continue
            first_char = line[0]
            if first_char.isdigit():
                line_index = int(first_char)
                remainder = line[1:]
                lines_dict.setdefault(line_index, []).append(remainder)
            elif first_char in ("E", "S"):
                # StartExecutePSFirst / EndExecutePSFirst - ignore
                pass
            else:
                logger.debug("Unexpected character in scripts.ini line: %s", line)

        for _subsection_idx, sub_lines in lines_dict.items():
            script_setting = ScriptSetting(source=filepath, script_type=script_type)

            for sub_line in sub_lines:
                if "=" in sub_line:
                    key, _, value = sub_line.partition("=")
                    if key == "CmdLine":
                        script_setting.cmd_line = value
                    elif key == "Parameters":
                        script_setting.parameters = value
                    else:
                        logger.debug("Unknown scripts.ini key: %s", key)

            settings.append(script_setting)

    return settings
