"""SYSVOL directory loading and GPO enumeration."""

from __future__ import annotations

import logging
import os
import re

from ..models.enums import PolicyType
from ..models.gpo import GPO
from ..models.settings import GpoSetting
from ..parsers.file_factory import parse_gpo_file

logger = logging.getLogger(__name__)

# GUID pattern to identify GPO directories
_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)


def load_sysvol_offline(sysvol_path: str) -> list[GPO]:
    """Load and parse GPOs from a local SYSVOL directory.

    The sysvol_path should point to a directory containing a 'Policies' subdirectory,
    or directly to a Policies directory containing GUID-named GPO folders.
    """
    if not os.path.isdir(sysvol_path):
        raise FileNotFoundError(f"SYSVOL path not found: {sysvol_path}")

    gpo_dirs = _enumerate_gpo_directories(sysvol_path)
    logger.info("Found %d GPO directories", len(gpo_dirs))

    return _enumerate_sysvol_gpos(gpo_dirs)


def _enumerate_gpo_directories(sysvol_path: str) -> list[str]:
    """Walk SYSVOL to find GPO directories (GUID-named folders under Policies)."""
    gpo_dirs: list[str] = []

    try:
        entries = os.listdir(sysvol_path)
    except OSError as e:
        logger.error("Failed to list SYSVOL: %s", e)
        return gpo_dirs

    for entry in entries:
        full_path = os.path.join(sysvol_path, entry)
        if not os.path.isdir(full_path):
            continue

        if "policies" in entry.lower():
            if "ntfrs" in entry.lower():
                logger.debug("Found morphed policies directory: %s", full_path)

            try:
                for subdir in os.listdir(full_path):
                    subdir_path = os.path.join(full_path, subdir)
                    if os.path.isdir(subdir_path) and _GUID_RE.match(subdir):
                        gpo_dirs.append(subdir_path)
                        logger.debug("Found GPO dir: %s", subdir_path)
            except OSError as e:
                logger.error("Failed to list directory %s: %s", full_path, e)
        elif _GUID_RE.match(entry):
            # sysvol_path might already be the Policies directory
            gpo_dirs.append(full_path)

    return gpo_dirs


def _list_all_files(directory: str) -> list[str]:
    """Recursively list all files in a directory."""
    files: list[str] = []
    for root, _dirs, filenames in os.walk(directory):
        for filename in filenames:
            files.append(os.path.join(root, filename))
    return files


def _determine_policy_type(filepath: str) -> PolicyType:
    """Determine if a file is under Machine or User policy based on its path."""
    filepath_lower = filepath.lower()
    sep = os.sep
    if f"{sep}machine{sep}" in filepath_lower or "/machine/" in filepath_lower:
        return PolicyType.COMPUTER
    elif f"{sep}user{sep}" in filepath_lower or "/user/" in filepath_lower:
        return PolicyType.USER
    else:
        logger.debug("Cannot determine policy type from path: %s", filepath)
        return PolicyType.COMPUTER


def _enumerate_sysvol_gpos(gpo_dirs: list[str]) -> list[GPO]:
    """Parse all GPO directories into GPO objects."""
    gpos: list[GPO] = []

    for gpo_dir in gpo_dirs:
        gpo_uid = os.path.basename(gpo_dir)
        is_morphed = "ntfrs" in gpo_dir.lower()

        gpo = GPO(uid=gpo_uid, path_in_sysvol=gpo_dir, morphed=is_morphed)

        files = _list_all_files(gpo_dir)
        for filepath in files:
            try:
                parsed_settings = parse_gpo_file(filepath)
                if parsed_settings:
                    gpo.gpo_files.append(filepath)
                    policy_type = _determine_policy_type(filepath)
                    for setting in parsed_settings:
                        setting.policy_type = policy_type
                        setting.is_morphed = is_morphed
                        gpo.settings.append(setting)
            except Exception as e:
                logger.debug("Error parsing %s: %s", filepath, e)

        if gpo.settings:
            gpos.append(gpo)

    return gpos
