"""Active Directory enumeration orchestrator combining LDAP and SMB."""

from __future__ import annotations

import logging
from typing import Optional

from ..models.gpo import GPO
from .ldap_client import LdapClient
from .smb_client import SmbClient

logger = logging.getLogger(__name__)


class ActiveDirectory:
    """High-level AD interface combining LDAP and SMB for GPO enumeration.

    Reads SYSVOL files in-memory over SMB (no temp files), matching
    the original Group3r behavior of reading via UNC paths.
    """

    def __init__(self, target_domain: str, dc_ip: str = "",
                 dc_host: str = "",
                 username: str = "", password: str = "",
                 hashes: str = "", use_kerberos: bool = False,
                 auth_domain: str = ""):
        self.target_domain = target_domain
        self.dc_ip = dc_ip
        self.dc_host = dc_host
        self.auth_domain = auth_domain or target_domain
        self.ldap = LdapClient(
            target_domain=target_domain, dc_ip=dc_ip,
            dc_host=dc_host,
            username=username, password=password,
            hashes=hashes, use_kerberos=use_kerberos,
            auth_domain=self.auth_domain,
        )
        self.smb = SmbClient(
            domain=self.auth_domain, dc_ip=dc_ip,
            dc_host=dc_host,
            username=username, password=password,
            hashes=hashes, use_kerberos=use_kerberos,
            target_domain=target_domain,
        )

    def enumerate_gpos(self) -> list[GPO]:
        """Full GPO enumeration: LDAP metadata + SYSVOL files read in-memory.

        1. LDAP: enumerate GPO objects (metadata, ACLs, links)
        2. SMB: read and parse SYSVOL policy files in-memory
        3. Merge LDAP metadata with parsed settings
        """
        # Step 1: GPO metadata from LDAP
        logger.info("Step 1: LDAP GPO enumeration...")
        self.ldap.connect()
        ldap_gpos = self.ldap.enumerate_gpos()
        logger.info("Found %d GPOs in LDAP", len(ldap_gpos))

        if not ldap_gpos:
            logger.warning("No GPOs found via LDAP.")
            return []

        # Build lookup by UID
        gpo_by_uid: dict[str, GPO] = {}
        for gpo in ldap_gpos:
            uid = gpo.attributes.uid.strip("{}").lower()
            gpo_by_uid[uid] = gpo

        # Step 2: Read and parse SYSVOL files in-memory via SMB
        logger.info("Step 2: Reading SYSVOL via SMB (in-memory)...")
        try:
            sysvol_gpos = self.smb.enumerate_and_parse_sysvol()
        except Exception as e:
            logger.error("SMB SYSVOL read failed: %s", e)
            logger.info("Returning GPOs with LDAP metadata only (no parsed settings).")
            return ldap_gpos

        logger.info("Parsed %d GPOs from SYSVOL", len(sysvol_gpos))

        # Step 3: Merge parsed settings into LDAP GPO objects
        for sysvol_gpo in sysvol_gpos:
            uid = sysvol_gpo.attributes.uid.strip("{}").lower()
            if uid in gpo_by_uid:
                gpo_by_uid[uid].settings = sysvol_gpo.settings
                gpo_by_uid[uid].gpo_files = sysvol_gpo.gpo_files
            else:
                logger.debug("GPO %s in SYSVOL but not LDAP (orphaned)", uid)
                gpo_by_uid[uid] = sysvol_gpo

        # Get GPO links (one bulk query for all OUs, matching original C# approach)
        all_gpos = list(gpo_by_uid.values())
        try:
            self.ldap.enumerate_gpo_links(all_gpos)
        except Exception as e:
            logger.debug("Failed to enumerate GPO links: %s", e)

        return list(gpo_by_uid.values())

    def cleanup(self) -> None:
        """Close connections."""
        self.ldap.close()
        self.smb.close()
