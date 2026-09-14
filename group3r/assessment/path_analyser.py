"""Analyse UNC paths referenced by GPOs for write access (Group3r PathAnalyser)."""

from __future__ import annotations

import logging
from ..models.findings import PathResult
from .sddl_analyser import analyse_sddl
from .trustee_match import match_trustee

logger = logging.getLogger(__name__)


def analyse_setting_path(options, path: str) -> PathResult:
    pa = getattr(options, "path_analyser", None)
    if pa is not None:
        return pa.analyse(path)
    return PathResult(path=path or "")

_WRITE_RIGHTS = {
    "CREATE_LINK", "WRITE", "WRITE_OWNER", "WRITE_DAC", "APPEND_DATA",
    "WRITE_DATA", "CREATE_CHILD", "FILE_WRITE", "ADD_FILE", "ADD_SUBDIRECTORY",
    "Owner", "GENERIC_WRITE", "GENERIC_ALL", "FILE_ALL", "ALL_ACCESS",
    "STANDARD_RIGHTS_ALL", "DELETE_CHILD",
}

_SKIP_OWNERS = {
    "administrators", "administrator", "system", "local system",
    "nt authority\\system", "builtin\\administrators",
}


class PathAnalyser:
    """Check UNC (and local) paths for existence and low-priv/target write."""

    def __init__(self, options, smb_client=None):
        self.options = options
        self.smb = smb_client

    def analyse(self, path: str) -> PathResult:
        result = PathResult(path=path)
        if not path:
            return result

        from .path_utils import is_unc, path_exists

        if is_unc(path):
            if self.smb is None:
                return result
            return self._analyse_unc(path)

        import os
        if os.path.isfile(path):
            result.file_exists = True
        elif os.path.isdir(path):
            result.directory_exists = True
        elif path_exists(os.path.dirname(path)):
            result.parent_directory_writable = False
        return result

    def _analyse_unc(self, path: str) -> PathResult:
        result = PathResult(path=path)
        try:
            kind, sddl = self.smb.query_path_security(path)
        except Exception as e:
            logger.debug("UNC ACL query failed for %s: %s", path, e)
            return result

        if kind == "file":
            result.file_exists = True
            result.file_writable = self._sddl_writable(sddl)
        elif kind == "dir":
            result.directory_exists = True
            result.directory_writable = self._sddl_writable(sddl)
        elif kind == "parent":
            result.parent_directory_writable = self._sddl_writable(sddl)
        return result

    def _sddl_writable(self, sddl: str) -> bool:
        if not sddl:
            return False
        from ..sddl.parser import SddlDescriptor
        from ..sddl.constants import SecurableObjectType

        try:
            parsed = SddlDescriptor(sddl, SecurableObjectType.FILE)
            aces = analyse_sddl(parsed)
        except Exception as e:
            logger.debug("Failed to parse path SDDL: %s", e)
            return False

        for ace in aces:
            if ace.ace_type != "Allow":
                continue
            if not any(r in _WRITE_RIGHTS for r in ace.rights):
                continue
            trustee = (ace.trustee or "").lower()
            if trustee in _SKIP_OWNERS:
                continue
            to = match_trustee(self.options, ace.trustee, ace.trustee_sid)
            if not to:
                continue
            if to.get("display_name", "").lower() in _SKIP_OWNERS:
                continue
            if to.get("high_priv"):
                continue
            if to.get("low_priv") or to.get("target"):
                return True
        return False
