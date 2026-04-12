"""Factory to route GPO files to the appropriate parser."""

from __future__ import annotations

import logging
import os

from ..models.settings import GpoSetting
from .inf_parser import parse_inf_file
from .ini_parser import parse_ini_file
from .pol_parser import parse_pol_file
from .xml_parser import parse_xml_file

logger = logging.getLogger(__name__)

# Filenames/extensions we know how to parse
PARSEABLE_NAMES = {"gpttmpl.inf", "scripts.ini", "psscripts.ini", "registry.pol"}


def is_parseable(filename: str) -> bool:
    """Check if a filename is one we can parse."""
    name_lower = filename.lower()
    return name_lower in PARSEABLE_NAMES or name_lower.endswith(".xml")


def parse_gpo_file(filepath: str, content: bytes | None = None) -> list[GpoSetting]:
    """Parse a GPO file using the appropriate parser.

    Args:
        filepath: Path or UNC path (used for identification and hive detection).
        content: Raw file bytes. If None, reads from filepath on disk.

    Returns a list of GpoSetting objects, or empty list if unrecognized.
    """
    filename = os.path.basename(filepath).lower()

    if filename == "gpttmpl.inf":
        return parse_inf_file(filepath, content)
    elif filename in ("scripts.ini", "psscripts.ini"):
        return parse_ini_file(filepath, content)
    elif filename == "registry.pol":
        return parse_pol_file(filepath, content)
    elif filename.endswith(".xml"):
        return parse_xml_file(filepath, content)
    else:
        logger.debug("No parser for file: %s", filepath)
        return []
