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
        self._host_conns: dict = {}

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

    def enumerate_and_parse_sysvol(self, max_threads: int = 1) -> list[GPO]:
        """Read and parse GPO files directly from SYSVOL over SMB.

        No files are written to disk. Each file is read into memory,
        parsed, and the results are returned as GPO objects.
        """
        if not self._connection:
            self.connect()

        share = "SYSVOL"
        policies_paths = self._find_policies_paths(share)
        if not policies_paths:
            raise RuntimeError("Could not find Policies directory in SYSVOL share")

        logger.info("Reading GPOs from SYSVOL: %s", ", ".join(policies_paths))

        # List GPO directories (GUID-named folders), including NTFRS copies
        gpo_dirs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for policies_path in policies_paths:
            for item in self._list_gpo_dirs(share, policies_path):
                if item not in seen:
                    seen.add(item)
                    gpo_dirs.append(item)
        logger.info("Found %d GPO directories in SYSVOL", len(gpo_dirs))

        total = len(gpo_dirs)
        workers = max(1, min(max_threads or 1, total or 1))

        if workers <= 1:
            gpos = []
            for i, (gpo_uid, gpo_path) in enumerate(gpo_dirs, 1):
                print(f"\r[*] Reading SYSVOL: GPO {i}/{total}...",
                      end="", flush=True, file=__import__("sys").stderr)
                gpo = self._load_one_gpo(share, gpo_uid, gpo_path)
                if gpo and gpo.settings:
                    gpos.append(gpo)
            print(file=__import__("sys").stderr)
            logger.info("Parsed %d GPOs with settings from SYSVOL", len(gpos))
            return gpos

        from concurrent.futures import ThreadPoolExecutor, as_completed
        import threading
        done = 0
        lock = threading.Lock()
        gpos: list[GPO] = []

        def _job(item):
            uid, path = item
            client = self._clone()
            try:
                client.connect()
                return client._load_one_gpo(share, uid, path)
            finally:
                client.close()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futs = [pool.submit(_job, item) for item in gpo_dirs]
            for fut in as_completed(futs):
                with lock:
                    done += 1
                    print(f"\r[*] Reading SYSVOL: GPO {done}/{total}...",
                          end="", flush=True, file=__import__("sys").stderr)
                try:
                    gpo = fut.result()
                except Exception as e:
                    logger.debug("GPO worker failed: %s", e)
                    continue
                if gpo and gpo.settings:
                    gpos.append(gpo)
        print(file=__import__("sys").stderr)
        logger.info("Parsed %d GPOs with settings from SYSVOL", len(gpos))
        return gpos

    def _clone(self) -> "SmbClient":
        return SmbClient(
            domain=self.domain, dc_ip=self.dc_ip, dc_host=self.dc_host,
            username=self.username, password=self.password,
            hashes=self.hashes, use_kerberos=self.use_kerberos,
            target_domain=self.target_domain,
        )

    def _load_one_gpo(self, share: str, gpo_uid: str, gpo_path: str) -> GPO:
        is_morphed = "ntfrs" in gpo_path.lower()
        gpo = GPO(
            uid=gpo_uid,
            path_in_sysvol=f"\\\\{self.dc_ip or self.domain}\\{share}\\{gpo_path}",
            morphed=is_morphed,
        )
        self._parse_gpo_files(share, gpo_path, gpo)
        return gpo

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
        """Back-compat: first Policies directory found."""
        paths = self._find_policies_paths(share)
        return paths[0] if paths else None

    def _find_policies_paths(self, share: str) -> list[str]:
        """Find all Policies directories, including NTFRS/morphed copies.

        Matches C# Sysvol.EnumerateGPODirectories: any child whose name
        contains 'policies' is treated as a policy root.
        """
        found: list[str] = []

        def _consider(path: str) -> None:
            try:
                entries = self._connection.listPath(share, path + "/*")
            except Exception:
                return
            if entries:
                logger.info("Found Policies at: %s/%s", share, path)
                found.append(path)

        candidates = [self.target_domain]
        if self.domain != self.target_domain:
            candidates.append(self.domain)

        # Standard {domain}/Policies plus any sibling whose name contains 'policies'
        domain_folders: list[str] = []
        try:
            for entry in self._connection.listPath(share, "*"):
                name = entry.get_longname()
                if name in (".", "..") or not entry.is_directory():
                    continue
                domain_folders.append(name)
        except Exception as e:
            logger.error("Failed to list SYSVOL root: %s", e)

        search_roots = candidates + [n for n in domain_folders if n not in candidates]
        for domain in search_roots:
            try:
                entries = self._connection.listPath(share, domain + "/*")
            except Exception:
                continue
            for entry in entries:
                name = entry.get_longname()
                if name in (".", "..") or not entry.is_directory():
                    continue
                if "policies" in name.lower():
                    _consider(f"{domain}/{name}")

        # Last resort: {domain}/Policies even if listing the domain folder failed
        if not found:
            for domain in candidates:
                _consider(f"{domain}/Policies")

        return found

    def query_path_security(self, unc_path: str) -> tuple[str, str]:
        """Return (kind, sddl) for a UNC path.

        kind is 'file', 'dir', 'parent', or '' if nothing could be opened.
        """
        parsed = _parse_unc(unc_path)
        if not parsed:
            return "", ""
        host, share, rel = parsed
        conn = self._connection_for(host)
        if conn is None:
            return "", ""

        rel = rel.replace("/", "\\").lstrip("\\")
        kind, sddl = self._query_rel(conn, share, rel)
        if kind:
            return kind, sddl

        # Walk parents for a writable directory of a missing file
        parent = rel
        while True:
            if "\\" in parent:
                parent = parent.rsplit("\\", 1)[0]
            elif parent:
                parent = ""
            else:
                break
            kind, sddl = self._query_rel(conn, share, parent, prefer_dir=True)
            if kind == "dir":
                return "parent", sddl
        return "", ""

    def _connection_for(self, host: str):
        if not self._connection:
            self.connect()
        dc = (self.dc_host or self.dc_ip or self.target_domain or "").lower()
        if host.lower() in {dc, (self.dc_ip or "").lower(), (self.target_domain or "").lower()}:
            return self._connection
        cached = self._host_conns.get(host.lower())
        if cached is not None:
            return cached
        try:
            from impacket.smbconnection import SMBConnection
            remote_host = host
            conn = SMBConnection(host, remote_host)
            lm_hash = nt_hash = ""
            if self.hashes:
                parts = self.hashes.split(":", 1)
                lm_hash = parts[0]
                nt_hash = parts[1] if len(parts) > 1 else ""
            if self.use_kerberos:
                from .ldap_client import LdapClient
                kdc = self.dc_ip or self.target_domain
                TGT = LdapClient._get_tgt_from_ccache()
                conn.kerberosLogin(
                    self.username, self.password, self.domain,
                    lm_hash, nt_hash, kdcHost=kdc, TGT=TGT,
                )
            else:
                conn.login(self.username, self.password, self.domain, lm_hash, nt_hash)
            self._host_conns[host.lower()] = conn
            return conn
        except Exception as e:
            logger.debug("SMB connect to %s failed: %s", host, e)
            return None

    def _query_rel(self, conn, share: str, rel: str, prefer_dir: bool = False) -> tuple[str, str]:
        order = ("dir", "file") if prefer_dir else ("file", "dir")
        for kind in order:
            try:
                sddl = self._read_sddl(conn, share, rel, as_dir=(kind == "dir"))
                if sddl:
                    return kind, sddl
            except Exception as e:
                logger.debug("SMB %s open %s\\%s: %s", kind, share, rel, e)
        return "", ""

    def _read_sddl(self, conn, share: str, rel: str, as_dir: bool) -> str:
        from impacket.smb3structs import (
            FILE_READ_ATTRIBUTES, READ_CONTROL, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_SHARE_DELETE, FILE_NON_DIRECTORY_FILE,
            FILE_DIRECTORY_FILE, FILE_OPEN, SMB2_0_INFO_SECURITY,
        )
        from impacket import smb as smb_mod

        access = FILE_READ_ATTRIBUTES | READ_CONTROL
        share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        opts = FILE_DIRECTORY_FILE if as_dir else FILE_NON_DIRECTORY_FILE
        tree_id = conn.connectTree(share)
        fid = None
        try:
            fid = conn.openFile(
                tree_id, rel or "\\",
                desiredAccess=access,
                shareMode=share_mode,
                creationOption=opts,
                creationDisposition=FILE_OPEN,
            )
            if conn.getDialect() == smb_mod.SMB_DIALECT:
                buf = conn._SMBConnection.query_sec_info(tree_id, fid, 7)
            else:
                buf = conn._SMBConnection.queryInfo(
                    tree_id, fid,
                    infoType=SMB2_0_INFO_SECURITY,
                    fileInfoClass=0,
                    additionalInformation=7,
                )
            from ..sddl.from_binary import security_descriptor_to_sddl
            return security_descriptor_to_sddl(bytes(buf))
        finally:
            if fid is not None:
                try:
                    conn.closeFile(tree_id, fid)
                except Exception:
                    pass
            try:
                conn.disconnectTree(tree_id)
            except Exception:
                pass

    def close(self) -> None:
        """Close SMB connection."""
        for conn in list(self._host_conns.values()):
            try:
                conn.logoff()
            except Exception:
                pass
        self._host_conns.clear()
        if self._connection:
            try:
                self._connection.logoff()
            except Exception:
                pass
            self._connection = None


def _parse_unc(path: str) -> Optional[tuple[str, str, str]]:
    """Split \\\\host\\share\\rel into (host, share, rel)."""
    if not path:
        return None
    norm = path.replace("/", "\\")
    while norm.startswith("\\"):
        norm = norm[1:]
    parts = [p for p in norm.split("\\") if p]
    if len(parts) < 2:
        return None
    host, share = parts[0], parts[1]
    rel = "\\".join(parts[2:])
    return host, share, rel


def _determine_policy_type(filepath: str) -> PolicyType:
    """Determine if a file is under Machine or User policy."""
    path_lower = filepath.lower()
    if "/machine/" in path_lower or "\\machine\\" in path_lower:
        return PolicyType.COMPUTER
    elif "/user/" in path_lower or "\\user\\" in path_lower:
        return PolicyType.USER
    return PolicyType.COMPUTER
