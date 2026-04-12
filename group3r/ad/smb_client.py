"""SMB client for SYSVOL access using impacket.

Reads GPO files directly from SYSVOL over SMB in-memory (no temp files),
matching the original Group3r behavior of reading via UNC paths.
"""

from __future__ import annotations

import io
import logging
import os
import re
from typing import Optional

from ..models.enums import PolicyType
from ..models.gpo import GPO
from ..models.settings import GpoSetting
from ..parsers.file_factory import is_parseable, parse_gpo_file

logger = logging.getLogger(__name__)

_GUID_RE = re.compile(
    r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
)


class SmbClient:
    """SMB client that reads SYSVOL GPO files in-memory over SMB."""

    def __init__(self, domain: str, dc_ip: str = "", dc_host: str = "",
                 username: str = "", password: str = "",
                 hashes: str = "", use_kerberos: bool = False,
                 target_domain: str = ""):
        self.domain = domain  # auth domain
        self.dc_ip = dc_ip
        self.dc_host = dc_host
        self.username = username
        self.password = password
        self.hashes = hashes
        self.use_kerberos = use_kerberos
        self.target_domain = target_domain or domain
        self._connection = None

    def connect(self) -> None:
        """Establish SMB connection to the domain controller."""
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            raise ImportError("impacket is required for online mode: pip install impacket")

        # For Kerberos, use the DC FQDN so the SPN is correct (CIFS/<fqdn>).
        # Fall back to target_domain (the domain being enumerated), not
        # self.domain (auth domain) which may differ in cross-domain scenarios.
        target = self.dc_host or self.dc_ip or self.target_domain
        # SMBConnection(remoteName, remoteHost): remoteName is used for the
        # SPN, remoteHost is the actual address to connect to.
        remote_host = self.dc_ip or target
        logger.info("Connecting to SMB: %s", target)

        self._connection = SMBConnection(target, remote_host)

        lm_hash = ""
        nt_hash = ""
        if self.hashes:
            parts = self.hashes.split(":", 1)
            lm_hash = parts[0]
            nt_hash = parts[1] if len(parts) > 1 else ""

        try:
            if self.use_kerberos:
                from .ldap_client import LdapClient
                kdc = self.dc_ip or self.target_domain
                TGT = LdapClient._get_tgt_from_ccache()
                self._connection.kerberosLogin(
                    self.username, self.password, self.domain,
                    lm_hash, nt_hash, kdcHost=kdc, TGT=TGT,
                )
            else:
                self._connection.login(
                    self.username, self.password, self.domain,
                    lm_hash, nt_hash,
                )
        except Exception as e:
            logger.error("SMB authentication failed: %s", e)
            raise RuntimeError(f"SMB authentication to {target} failed: {e}") from e

        logger.info("Connected to SMB: %s", target)

    def enumerate_and_parse_sysvol(self) -> list[GPO]:
        """Read and parse GPO files directly from SYSVOL over SMB.

        No files are written to disk. Each file is read into memory,
        parsed, and the results are returned as GPO objects.
        """
        if not self._connection:
            self.connect()

        share = "SYSVOL"
        policies_path = self._find_policies_path(share)
        if not policies_path:
            raise RuntimeError("Could not find Policies directory in SYSVOL share")

        logger.info("Reading GPOs from SYSVOL: %s", policies_path)

        # List GPO directories (GUID-named folders)
        gpo_dirs = self._list_gpo_dirs(share, policies_path)
        logger.info("Found %d GPO directories in SYSVOL", len(gpo_dirs))

        gpos: list[GPO] = []
        total = len(gpo_dirs)
        for i, (gpo_uid, gpo_path) in enumerate(gpo_dirs, 1):
            print(f"\r[*] Reading SYSVOL: GPO {i}/{total}...",
                  end="", flush=True, file=__import__("sys").stderr)

            is_morphed = "ntfrs" in gpo_path.lower()
            gpo = GPO(uid=gpo_uid, path_in_sysvol=f"\\\\{self.dc_ip or self.domain}\\{share}\\{gpo_path}", morphed=is_morphed)

            # Recursively find and parse all parseable files in this GPO
            self._parse_gpo_files(share, gpo_path, gpo)

            if gpo.settings:
                gpos.append(gpo)

        print(file=__import__("sys").stderr)  # newline after progress
        logger.info("Parsed %d GPOs with settings from SYSVOL", len(gpos))
        return gpos

    def _list_gpo_dirs(self, share: str, policies_path: str) -> list[tuple[str, str]]:
        """List GUID-named GPO directories under the Policies path."""
        dirs: list[tuple[str, str]] = []
        try:
            entries = self._connection.listPath(share, policies_path + "/*")
            for entry in entries:
                name = entry.get_longname()
                if name in (".", ".."):
                    continue
                if entry.is_directory() and _GUID_RE.match(name):
                    dirs.append((name, f"{policies_path}/{name}"))
        except Exception as e:
            logger.error("Failed to list GPO directories: %s", e)
        return dirs

    def _parse_gpo_files(self, share: str, gpo_path: str, gpo: GPO) -> None:
        """Recursively find and parse parseable files in a GPO directory."""
        try:
            entries = self._connection.listPath(share, gpo_path + "/*")
        except Exception as e:
            logger.debug("Failed to list %s: %s", gpo_path, e)
            return

        for entry in entries:
            name = entry.get_longname()
            if name in (".", ".."):
                continue

            full_path = f"{gpo_path}/{name}"

            if entry.is_directory():
                self._parse_gpo_files(share, full_path, gpo)
            elif is_parseable(name):
                # Read file content into memory
                content = self._read_file(share, full_path)
                if content is None:
                    continue

                # Use the UNC-style path for source identification
                unc_path = f"\\\\{self.dc_ip or self.domain}\\{share}\\{full_path}"
                logger.debug("Parsing: %s (%d bytes)", name, len(content))

                try:
                    parsed = parse_gpo_file(unc_path, content=content)
                    if parsed:
                        gpo.gpo_files.append(unc_path)
                        policy_type = _determine_policy_type(full_path)
                        for setting in parsed:
                            setting.policy_type = policy_type
                            setting.is_morphed = gpo.attributes.is_morphed_gpo
                            gpo.settings.append(setting)
                except Exception as e:
                    logger.debug("Error parsing %s: %s", full_path, e)

    def _read_file(self, share: str, remote_path: str) -> Optional[bytes]:
        """Read a file from SMB share into memory."""
        buf = io.BytesIO()
        try:
            self._connection.getFile(share, remote_path, buf.write)
            return buf.getvalue()
        except Exception as e:
            logger.debug("Failed to read %s: %s", remote_path, e)
            return None

    def _find_policies_path(self, share: str) -> Optional[str]:
        """Find the Policies directory in the SYSVOL share."""
        candidates = [self.target_domain]
        if self.domain != self.target_domain:
            candidates.append(self.domain)

        for domain in candidates:
            path = f"{domain}/Policies"
            try:
                entries = self._connection.listPath(share, path + "/*")
                if entries:
                    logger.info("Found Policies at: %s/%s", share, path)
                    return path
            except Exception:
                logger.debug("Policies not found at %s/%s", share, path)

        # Fallback: discover domain folders
        try:
            entries = self._connection.listPath(share, "*")
            for entry in entries:
                name = entry.get_longname()
                if name in (".", "..") or not entry.is_directory():
                    continue
                try_path = f"{name}/Policies"
                try:
                    sub = self._connection.listPath(share, try_path + "/*")
                    if sub:
                        logger.info("Discovered Policies at: %s/%s", share, try_path)
                        return try_path
                except Exception:
                    continue
        except Exception as e:
            logger.error("Failed to list SYSVOL root: %s", e)

        return None

    def close(self) -> None:
        """Close SMB connection."""
        if self._connection:
            try:
                self._connection.logoff()
            except Exception:
                pass
            self._connection = None


def _determine_policy_type(filepath: str) -> PolicyType:
    """Determine if a file is under Machine or User policy."""
    path_lower = filepath.lower()
    if "/machine/" in path_lower or "\\machine\\" in path_lower:
        return PolicyType.COMPUTER
    elif "/user/" in path_lower or "\\user\\" in path_lower:
        return PolicyType.USER
    return PolicyType.COMPUTER
