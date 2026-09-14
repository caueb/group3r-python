"""LDAP client for Active Directory enumeration.

Uses impacket's LDAP client (handles NTLM signing/sealing and channel binding)
with ldap3 as a fallback.
"""

from __future__ import annotations

import logging
import ssl
from typing import Optional

from ..models.gpo import GPO, GPOAttributes, GPOLink

logger = logging.getLogger(__name__)

# LDAP attributes to retrieve for GPO objects
GPO_ATTRIBUTES = [
    "displayName", "cn", "gPCFileSysPath", "gPCMachineExtensionNames",
    "gPCUserExtensionNames", "whenCreated", "whenChanged",
    "nTSecurityDescriptor", "distinguishedName", "flags",
    "versionNumber", "gPLink", "gPCWQLFilter",
]


class LdapClient:
    """LDAP client for querying Active Directory.

    Supports cross-domain authentication: auth_domain is the domain of the
    user credentials, target_domain is the domain to enumerate GPOs from.

    Connection strategy (in order):
    1. impacket LDAP with NTLM signing (handles strongerAuthRequired)
    2. impacket LDAPS (port 636)
    3. ldap3 LDAPS fallback
    4. ldap3 LDAP+StartTLS fallback
    """

    def __init__(self, target_domain: str, dc_ip: str = "",
                 dc_host: str = "",
                 username: str = "", password: str = "",
                 hashes: str = "", use_kerberos: bool = False,
                 auth_domain: str = ""):
        self.target_domain = target_domain
        self.dc_ip = dc_ip
        self.dc_host = dc_host
        self.username = username
        self.password = password
        self.hashes = hashes
        self.use_kerberos = use_kerberos
        self.auth_domain = auth_domain or target_domain
        self._connection = None
        self._base_dn = ""
        self._backend = None  # "impacket" or "ldap3"

    def connect(self) -> None:
        """Establish LDAP connection, trying multiple strategies."""
        # For Kerberos the LDAP SPN must use the DC's real hostname
        # (e.g. LDAP/dc01.corp.local), so dc_host
        # takes priority.  For NTLM an IP is fine.
        target = self.dc_host or self.dc_ip or self.target_domain
        errors: list[str] = []

        # Strategy 1: impacket LDAP (port 389 with NTLM signing)
        try:
            logger.info("Trying impacket LDAP (389, NTLM signing) to %s ...", target)
            self._connect_impacket(target, use_ssl=False)
            logger.info("Connected via impacket LDAP with signing")
            return
        except Exception as e:
            msg = f"impacket LDAP (389): {e}"
            errors.append(msg)
            logger.debug("Failed: %s", msg)

        # Strategy 2: impacket LDAPS (port 636)
        try:
            logger.info("Trying impacket LDAPS (636) to %s ...", target)
            self._connect_impacket(target, use_ssl=True)
            logger.info("Connected via impacket LDAPS")
            return
        except Exception as e:
            msg = f"impacket LDAPS (636): {e}"
            errors.append(msg)
            logger.debug("Failed: %s", msg)

        # Strategy 3: ldap3 LDAPS
        try:
            logger.info("Trying ldap3 LDAPS (636) to %s ...", target)
            self._connect_ldap3(target, use_ssl=True, use_start_tls=False)
            logger.info("Connected via ldap3 LDAPS")
            return
        except Exception as e:
            msg = f"ldap3 LDAPS (636): {e}"
            errors.append(msg)
            logger.debug("Failed: %s", msg)

        # Strategy 4: ldap3 LDAP+StartTLS
        try:
            logger.info("Trying ldap3 LDAP+StartTLS (389) to %s ...", target)
            self._connect_ldap3(target, use_ssl=False, use_start_tls=True)
            logger.info("Connected via ldap3 LDAP+StartTLS")
            return
        except Exception as e:
            msg = f"ldap3 StartTLS (389): {e}"
            errors.append(msg)
            logger.debug("Failed: %s", msg)

        detail = "\n  ".join(errors)
        raise RuntimeError(
            f"All LDAP connection methods to {target} failed:\n  {detail}"
        )

    def _connect_impacket(self, target: str, use_ssl: bool = False) -> None:
        """Connect using impacket's LDAP client (supports NTLM signing/sealing)."""
        from impacket.ldap import ldap as impacket_ldap

        # Derive base DN from domain for the URL
        base_dn = ",".join(f"DC={part}" for part in self.target_domain.split("."))

        proto = "ldaps" if use_ssl else "ldap"
        # Don't include port in URL — impacket derives the Kerberos SPN from
        # it, and "LDAP/host:389" is not a valid SPN.  ldap:// defaults to
        # 389 and ldaps:// defaults to 636, so omitting is correct.
        url = f"{proto}://{target}"

        logger.debug("impacket LDAP URL: %s, base DN: %s", url, base_dn)

        ldap_conn = impacket_ldap.LDAPConnection(url, base_dn, target)

        lm_hash = ""
        nt_hash = ""
        if self.hashes:
            parts = self.hashes.split(":", 1)
            lm_hash = parts[0]
            nt_hash = parts[1] if len(parts) > 1 else ""

        if self.use_kerberos:
            kdc = self.dc_ip or self.target_domain
            TGT = self._get_tgt_from_ccache()
            ldap_conn.kerberosLogin(
                self.username, self.password, self.auth_domain,
                lm_hash, nt_hash, kdcHost=kdc, TGT=TGT,
            )
        else:
            ldap_conn.login(
                self.username, self.password, self.auth_domain,
                lm_hash, nt_hash,
            )

        self._connection = ldap_conn
        self._backend = "impacket"

        # Discover base DN from RootDSE
        self._base_dn = self._discover_base_dn_impacket(ldap_conn) or base_dn
        logger.info("Base DN: %s", self._base_dn)

    @staticmethod
    def _get_tgt_from_ccache():
        """Load the TGT from the Kerberos credential cache (KRB5CCNAME).

        Returns the TGT dict expected by impacket's kerberosLogin, or None
        if no TGT is found (in which case impacket will request one from
        the KDC using the supplied credentials).
        """
        import os
        from impacket.krb5.ccache import CCache

        ccache_file = os.environ.get("KRB5CCNAME")
        if not ccache_file:
            return None

        ccache = CCache.loadFile(ccache_file)
        if ccache is None:
            return None

        # Look for a krbtgt ticket (the TGT) — do NOT use getCredential()
        # with anySPN because that returns arbitrary tickets.
        realm = ccache.principal.realm["data"].decode("utf-8").upper()
        tgt_principal = f"KRBTGT/{realm}@{realm}"
        for cred in ccache.credentials:
            if cred["server"].prettyPrint().decode("utf-8").upper() == tgt_principal:
                logger.debug("Extracted TGT from ccache for %s", tgt_principal)
                return cred.toTGT()

        logger.debug("No TGT found in ccache")
        return None

    def _connect_ldap3(self, target: str, use_ssl: bool, use_start_tls: bool) -> None:
        """Connect using ldap3 library."""
        import ldap3

        tls_ctx = ldap3.Tls(validate=ssl.CERT_NONE)
        port = 636 if use_ssl else 389
        server = ldap3.Server(
            target, port=port, use_ssl=use_ssl,
            get_info=ldap3.ALL, tls=tls_ctx,
        )

        bind_dn = f"{self.auth_domain}\\{self.username}" if self.username else None

        if self.use_kerberos:
            conn = ldap3.Connection(
                server, authentication=ldap3.SASL,
                sasl_mechanism=ldap3.KERBEROS,
            )
        elif self.username and self.password:
            conn = ldap3.Connection(
                server, user=bind_dn, password=self.password,
                authentication=ldap3.NTLM,
            )
        elif self.username and self.hashes:
            lm_hash, nt_hash = (self.hashes.split(":", 1)
                                if ":" in self.hashes else ("", self.hashes))
            conn = ldap3.Connection(
                server, user=bind_dn,
                password=lm_hash + ":" + nt_hash,
                authentication=ldap3.NTLM,
            )
        else:
            conn = ldap3.Connection(server)

        conn.open()
        if use_start_tls and not use_ssl:
            conn.start_tls()
        conn.bind()

        if conn.result["result"] != 0:
            desc = conn.result.get("description", "unknown")
            msg = conn.result.get("message", "")
            conn.unbind()
            raise RuntimeError(f"{desc} - {msg}")

        self._connection = conn
        self._backend = "ldap3"

        # Discover base DN
        if server.info and server.info.other:
            naming_ctx = server.info.other.get("defaultNamingContext")
            if naming_ctx:
                dn = naming_ctx[0] if isinstance(naming_ctx, list) else str(naming_ctx)
                if dn:
                    self._base_dn = dn
                    logger.info("Base DN from RootDSE: %s", self._base_dn)
                    return

        self._base_dn = ",".join(f"DC={part}" for part in self.target_domain.split("."))
        logger.info("Base DN from domain: %s", self._base_dn)

    def _discover_base_dn_impacket(self, ldap_conn) -> Optional[str]:
        """Read defaultNamingContext from RootDSE via impacket."""
        from impacket.ldap import ldapasn1 as ldapasn1

        try:
            search_filter = "(objectClass=*)"
            resp = ldap_conn.search(
                searchBase="",
                searchFilter=search_filter,
                scope=ldapasn1.Scope("baseObject"),
                attributes=["defaultNamingContext"],
            )
            for item in resp:
                if not isinstance(item, ldapasn1.SearchResultEntry):
                    continue
                for attr in item["attributes"]:
                    if str(attr["type"]) == "defaultNamingContext":
                        vals = attr["vals"]
                        if vals:
                            dn = str(vals[0])
                            logger.info("Base DN from RootDSE: %s", dn)
                            return dn
        except Exception as e:
            logger.debug("RootDSE query failed: %s", e)
        return None

    def enumerate_gpos(self) -> list[GPO]:
        """Enumerate all GPOs from Active Directory via LDAP."""
        if not self._connection:
            self.connect()

        if self._backend == "impacket":
            return self._enumerate_gpos_impacket()
        else:
            return self._enumerate_gpos_ldap3()

    def _enumerate_gpos_impacket(self) -> list[GPO]:
        """Enumerate GPOs using impacket LDAP."""
        from impacket.ldap import ldapasn1

        gpos: list[GPO] = []
        search_base = f"CN=Policies,CN=System,{self._base_dn}"
        logger.info("Searching for GPOs in: %s", search_base)

        try:
            resp = self._search_impacket(
                search_base, "(objectClass=groupPolicyContainer)",
                GPO_ATTRIBUTES, sd_flags=True,
            )
        except Exception as e:
            logger.error("LDAP GPO search failed: %s", e)
            raise RuntimeError(f"LDAP GPO search failed: {e}") from e

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            gpo = GPO()
            attrs = gpo.attributes

            for attr in item["attributes"]:
                attr_name = str(attr["type"])
                vals = attr["vals"]
                if not vals:
                    continue
                val = str(vals[0])

                if attr_name == "displayName":
                    attrs.display_name = val
                elif attr_name == "cn":
                    attrs.uid = val
                elif attr_name == "distinguishedName":
                    attrs.distinguished_name = val
                elif attr_name == "gPCFileSysPath":
                    attrs.path_in_sysvol = val
                elif attr_name == "versionNumber":
                    attrs.version_number = val
                elif attr_name == "whenCreated":
                    attrs.created_date = _parse_ldap_timestamp(val)
                elif attr_name == "whenChanged":
                    attrs.modified_date = _parse_ldap_timestamp(val)
                elif attr_name == "flags":
                    try:
                        flags = int(val)
                        attrs.user_policy_enabled = not (flags & 1)
                        attrs.computer_policy_enabled = not (flags & 2)
                    except ValueError:
                        pass
                elif attr_name == "gPCWQLFilter":
                    attrs.wmi_filter_dn = _wmi_filter_dn(val)
                elif attr_name == "nTSecurityDescriptor":
                    try:
                        raw = bytes(vals[0])
                        from ..sddl.from_binary import security_descriptor_to_sddl
                        attrs.nt_security_descriptor = security_descriptor_to_sddl(raw)
                    except Exception as e:
                        logger.debug("Failed to parse SD: %s", e)

            gpos.append(gpo)

        logger.info("Enumerated %d GPOs from LDAP", len(gpos))
        return gpos

    def _enumerate_gpos_ldap3(self) -> list[GPO]:
        """Enumerate GPOs using ldap3."""
        import ldap3

        gpos: list[GPO] = []
        search_base = f"CN=Policies,CN=System,{self._base_dn}"
        logger.info("Searching for GPOs in: %s", search_base)

        try:
            result = self._search_ldap3(
                search_base, "(objectClass=groupPolicyContainer)",
                GPO_ATTRIBUTES, sd_flags=True,
            )
        except Exception as e:
            logger.error("LDAP search failed: %s", e)
            raise RuntimeError(f"LDAP GPO search failed: {e}") from e

        if not result:
            logger.warning("LDAP search returned no GPO results")
            return gpos

        for entry in result:
            gpo = GPO()
            attrs = gpo.attributes
            attrs.display_name = str(entry.displayName) if hasattr(entry, "displayName") else ""
            attrs.uid = str(entry.cn) if hasattr(entry, "cn") else ""
            attrs.distinguished_name = (str(entry.distinguishedName)
                                        if hasattr(entry, "distinguishedName") else "")
            attrs.path_in_sysvol = (str(entry.gPCFileSysPath)
                                    if hasattr(entry, "gPCFileSysPath") else "")
            attrs.version_number = (str(entry.versionNumber)
                                    if hasattr(entry, "versionNumber") else "")
            if hasattr(entry, "whenCreated") and entry.whenCreated.value:
                attrs.created_date = entry.whenCreated.value
            if hasattr(entry, "whenChanged") and entry.whenChanged.value:
                attrs.modified_date = entry.whenChanged.value
            if hasattr(entry, "flags") and entry.flags.value is not None:
                try:
                    flags = int(entry.flags.value)
                    attrs.user_policy_enabled = not (flags & 1)
                    attrs.computer_policy_enabled = not (flags & 2)
                except (ValueError, TypeError):
                    pass
            if hasattr(entry, "gPCWQLFilter") and entry.gPCWQLFilter.value:
                attrs.wmi_filter_dn = _wmi_filter_dn(str(entry.gPCWQLFilter.value))
            if hasattr(entry, "nTSecurityDescriptor") and entry.nTSecurityDescriptor.value:
                try:
                    raw = entry.nTSecurityDescriptor.value
                    if isinstance(raw, list):
                        raw = raw[0]
                    from ..sddl.from_binary import security_descriptor_to_sddl
                    attrs.nt_security_descriptor = security_descriptor_to_sddl(bytes(raw))
                except Exception as e:
                    logger.debug("Failed to parse SD for %s: %s", attrs.uid, e)
            gpos.append(gpo)

        logger.info("Enumerated %d GPOs from LDAP", len(gpos))
        return gpos

    def enumerate_gpo_links(self, gpos: list[GPO]) -> None:
        """Enumerate all GPO links in one bulk query and distribute to GPOs.

        Matches the original C# EnumerateDomainGpoLinks() approach:
        1. Query ALL OUs/sites/domains for 'gplink' attribute
        2. Parse gplink format: [LDAP://CN={GUID},...;status][...]
        3. Match each link back to GPO by distinguished name
        4. Set LinkPath = OU's DN, LinkEnforced = status string
        """
        if not self._connection:
            return

        # Build GPO lookup by distinguished name (case-insensitive)
        gpo_by_dn: dict[str, GPO] = {}
        for gpo in gpos:
            dn = gpo.attributes.distinguished_name
            if dn:
                gpo_by_dn[dn.lower()] = gpo

        if not gpo_by_dn:
            return

        logger.info("Enumerating GPO links from OUs/sites/domains...")

        # Status code mapping (matches C# switch exactly)
        # gpLink status is a bitmask: bit 0 = disabled, bit 1 = enforced
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/08090b22-bc16-49f4-8e10-f27a8fb16d18
        status_map = {
            "0": "Enabled, Unenforced",   # no bits set
            "1": "Disabled, Unenforced",  # bit 0 (disabled)
            "2": "Enabled, Enforced",     # bit 1 (enforced)
            "3": "Disabled, Enforced",    # both bits
        }

        if self._backend == "impacket":
            self._enumerate_links_impacket(gpo_by_dn, status_map)
        else:
            self._enumerate_links_ldap3(gpo_by_dn, status_map)

        total = sum(len(g.attributes.gpo_links) for g in gpos)
        logger.info("Found %d GPO links total", total)

    def _enumerate_links_impacket(self, gpo_by_dn: dict[str, GPO],
                                   status_map: dict[str, str]) -> None:
        from impacket.ldap import ldapasn1
        import re

        ldap_filter = "(|(objectClass=organizationalUnit)(objectClass=site)(objectClass=domain))"
        try:
            resp = self._search_impacket(
                self._base_dn, ldap_filter,
                ["distinguishedName", "gplink", "gpoptions"],
            )
        except Exception as e:
            logger.debug("Failed to enumerate GPO links: %s", e)
            return

        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue

            ou_dn = ""
            gplink_val = ""
            for attr in item["attributes"]:
                name = str(attr["type"]).lower()
                if name == "distinguishedname" and attr["vals"]:
                    ou_dn = str(attr["vals"][0])
                elif name == "gplink" and attr["vals"]:
                    gplink_val = str(attr["vals"][0])

            if not gplink_val:
                continue

            self._parse_gplink(gplink_val, ou_dn, gpo_by_dn, status_map)

    def _enumerate_links_ldap3(self, gpo_by_dn: dict[str, GPO],
                                status_map: dict[str, str]) -> None:
        import ldap3

        ldap_filter = "(|(objectClass=organizationalUnit)(objectClass=site)(objectClass=domain))"
        try:
            entries = self._search_ldap3(
                self._base_dn, ldap_filter,
                ["distinguishedName", "gplink", "gpoptions"],
            )
        except Exception as e:
            logger.debug("Failed to enumerate GPO links: %s", e)
            return

        for entry in entries:
            ou_dn = str(entry.distinguishedName) if hasattr(entry, "distinguishedName") else ""
            gplink_val = str(entry.gplink) if hasattr(entry, "gplink") and entry.gplink.value else ""
            if gplink_val:
                self._parse_gplink(gplink_val, ou_dn, gpo_by_dn, status_map)

    @staticmethod
    def _parse_gplink(gplink_val: str, ou_dn: str,
                       gpo_by_dn: dict[str, GPO],
                       status_map: dict[str, str]) -> None:
        """Parse a gplink attribute value and add links to matching GPOs.

        Format: [LDAP://CN={GUID},CN=Policies,CN=System,DC=...;status][...]
        """
        # Split on ] and [ to get individual link entries
        parts = gplink_val.replace("][", "]\x00[").split("\x00")
        for part in parts:
            part = part.strip("[] ")
            if not part.startswith("LDAP"):
                continue

            # Split on ; to get DN and status
            split_link = part.split(";")
            if len(split_link) < 2:
                continue

            dn_part = split_link[0]
            status_code = split_link[1].strip()

            # Extract the CN=... part from LDAP://CN=...
            cn_idx = dn_part.upper().find("CN=")
            if cn_idx < 0:
                continue
            gpo_dn = dn_part[cn_idx:]

            # Look up the GPO
            gpo = gpo_by_dn.get(gpo_dn.lower())
            if gpo is None:
                logger.debug("GPO link target not found: %s", gpo_dn)
                continue

            link = GPOLink(
                link_path=ou_dn,
                link_enforced=status_map.get(status_code, ""),
            )
            gpo.attributes.gpo_links.append(link)

    def enumerate_gpo_packages(self, gpos: list[GPO]) -> None:
        """Attach software installation (packageRegistration) settings to GPOs.

        Mirrors C# ActiveDirectory.EnumerateGpoPackages().
        """
        if not self._connection:
            return
        if self._backend == "impacket":
            self._enumerate_packages_impacket(gpos)
        else:
            self._enumerate_packages_ldap3(gpos)

    def _attach_package(self, gpos: list[GPO], attrs: dict) -> None:
        from ..models.enums import PolicyType
        from ..models.settings import PackageSetting

        dn = attrs.get("distinguishedName") or ""
        if not dn:
            return
        parts = [p.strip() for p in dn.split(",")]
        if len(parts) < 5:
            return
        try:
            parent_gpo = parts[len(parts) - 5].split("=", 1)[1]
        except (IndexError, ValueError):
            return

        pkg = PackageSetting(source="LDAP")
        pkg.display_name = attrs.get("displayName") or ""
        pkg.distinguished_name = dn
        pkg.cn = attrs.get("cn") or ""
        pkg.parent_gpo = parent_gpo
        pkg.msi_script_name = attrs.get("msiScriptName") or ""
        pkg.created_date = attrs.get("whenCreated")
        pkg.modified_date = attrs.get("whenChanged")
        pkg.policy_type = PolicyType.PACKAGE

        msi_list = attrs.get("msiFileList") or []
        if isinstance(msi_list, str):
            msi_list = [msi_list]
        for entry in msi_list:
            for path in str(entry).split(":"):
                path = path.strip()
                if not path or path == "0":
                    continue
                pkg.msi_file_list.append(path)

        if len(parts) > 3 and parts[3].lower() == "cn=user":
            script = pkg.msi_script_name
            if script == "A":
                pkg.package_action = "User Assigned"
            elif script == "P":
                pkg.package_action = "User Published"
            elif script == "R":
                pkg.package_action = "Package Removed"
        else:
            pkg.package_action = "Computer Assigned"

        parent_uid = parent_gpo.strip("{}").lower()
        for gpo in gpos:
            if gpo.attributes.uid.strip("{}").lower() == parent_uid:
                gpo.settings.append(pkg)
                return

    def _enumerate_packages_impacket(self, gpos: list[GPO]) -> None:
        from impacket.ldap import ldapasn1

        try:
            resp = self._search_impacket(
                self._base_dn, "(objectClass=packageRegistration)",
                [
                    "displayName", "distinguishedName", "msiFileList",
                    "msiScriptName", "productCode", "whenCreated",
                    "whenChanged", "upgradeProductCode", "cn",
                ],
            )
        except Exception as e:
            logger.debug("Package LDAP search failed: %s", e)
            return

        count = 0
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            attrs: dict = {}
            for attr in item["attributes"]:
                name = str(attr["type"])
                vals = attr["vals"]
                if not vals:
                    continue
                if name == "msiFileList":
                    attrs[name] = [str(v) for v in vals]
                elif name in ("whenCreated", "whenChanged"):
                    attrs[name] = _parse_ldap_timestamp(str(vals[0]))
                else:
                    attrs[name] = str(vals[0])
            self._attach_package(gpos, attrs)
            count += 1
        logger.info("Attached %d software packages from LDAP", count)

    def _enumerate_packages_ldap3(self, gpos: list[GPO]) -> None:
        import ldap3

        try:
            entries = self._search_ldap3(
                self._base_dn, "(objectClass=packageRegistration)",
                [
                    "displayName", "distinguishedName", "msiFileList",
                    "msiScriptName", "productCode", "whenCreated",
                    "whenChanged", "upgradeProductCode", "cn",
                ],
            )
        except Exception as e:
            logger.debug("Package LDAP search failed: %s", e)
            return

        count = 0
        for entry in entries:
            attrs: dict = {
                "displayName": str(entry.displayName) if hasattr(entry, "displayName") else "",
                "distinguishedName": (
                    str(entry.distinguishedName) if hasattr(entry, "distinguishedName") else ""
                ),
                "cn": str(entry.cn) if hasattr(entry, "cn") else "",
                "msiScriptName": (
                    str(entry.msiScriptName) if hasattr(entry, "msiScriptName") else ""
                ),
            }
            if hasattr(entry, "msiFileList") and entry.msiFileList.value:
                val = entry.msiFileList.value
                attrs["msiFileList"] = val if isinstance(val, list) else [val]
            if hasattr(entry, "whenCreated") and entry.whenCreated.value:
                attrs["whenCreated"] = entry.whenCreated.value
            if hasattr(entry, "whenChanged") and entry.whenChanged.value:
                attrs["whenChanged"] = entry.whenChanged.value
            self._attach_package(gpos, attrs)
            count += 1
        logger.info("Attached %d software packages from LDAP", count)

    def _search_impacket(self, base: str, search_filter: str,
                         attributes: list[str], sd_flags: bool = False):
        from impacket.ldap.ldapasn1 import SimplePagedResultsControl, SDFlagsControl

        controls = [SimplePagedResultsControl(size=1000)]
        if sd_flags:
            controls.append(SDFlagsControl(flags=0x07))
        return self._connection.search(
            searchBase=base,
            searchFilter=search_filter,
            attributes=attributes,
            searchControls=controls,
        )

    def _search_ldap3(self, base: str, search_filter: str,
                      attributes: list[str], sd_flags: bool = False):
        import ldap3

        controls = None
        if sd_flags:
            from ldap3.protocol.microsoft import security_descriptor_control
            controls = security_descriptor_control(sdflags=7)

        entries = []
        cookie = True
        while cookie:
            kwargs = dict(
                search_base=base,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=attributes,
                paged_size=1000,
            )
            if controls is not None:
                kwargs["controls"] = controls
            if cookie is not True:
                kwargs["paged_cookie"] = cookie
            self._connection.search(**kwargs)
            entries.extend(list(self._connection.entries))
            cookie = None
            ctrls = (self._connection.result or {}).get("controls") or {}
            paged = ctrls.get("1.2.840.113556.1.4.319") or {}
            value = paged.get("value") or {}
            cookie = value.get("cookie") or None
        return entries

    def enumerate_target_trustees(self, username: str) -> list[dict]:
        """Resolve the bind user and nested groups as Target trustees.

        Uses tokenGroups (nested membership) rather than recursive member= walks.
        """
        if not username or not self._connection:
            return []
        sam = username.split("\\")[-1].split("@")[0]
        if self._backend == "impacket":
            return self._target_trustees_impacket(sam)
        return self._target_trustees_ldap3(sam)

    def _target_trustees_impacket(self, sam: str) -> list[dict]:
        from impacket.ldap import ldapasn1
        from impacket.ldap.ldaptypes import LDAP_SID

        try:
            resp = self._search_impacket(
                self._base_dn,
                f"(&(objectClass=user)(sAMAccountName={_ldap_escape(sam)}))",
                ["distinguishedName", "objectSid", "cn", "sAMAccountName"],
            )
        except Exception as e:
            logger.debug("Target user search failed: %s", e)
            return [{"display_name": sam, "sid": "", "target": True}]

        user_dn = ""
        user_sid = ""
        user_cn = sam
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            for attr in item["attributes"]:
                name = str(attr["type"])
                if not attr["vals"]:
                    continue
                if name == "distinguishedName":
                    user_dn = str(attr["vals"][0])
                elif name == "cn":
                    user_cn = str(attr["vals"][0])
                elif name == "objectSid":
                    try:
                        user_sid = LDAP_SID(data=bytes(attr["vals"][0])).formatCanonical()
                    except Exception:
                        user_sid = ""
            if user_dn:
                break
        if not user_dn:
            logger.warning("Failed to find target user %s in domain", sam)
            return [{"display_name": sam, "sid": "", "target": True}]

        results = [{"display_name": user_cn, "sid": user_sid, "target": True}]
        try:
            from impacket.ldap.ldapasn1 import Scope
            resp = self._connection.search(
                searchBase=user_dn,
                searchFilter="(objectClass=*)",
                scope=Scope("baseObject"),
                attributes=["tokenGroups"],
            )
        except Exception as e:
            logger.debug("tokenGroups query failed: %s", e)
            return results

        sids: list[str] = []
        for item in resp:
            if not isinstance(item, ldapasn1.SearchResultEntry):
                continue
            for attr in item["attributes"]:
                if str(attr["type"]) == "tokenGroups":
                    for val in attr["vals"]:
                        try:
                            sids.append(LDAP_SID(data=bytes(val)).formatCanonical())
                        except Exception:
                            pass
        results.extend(self._resolve_group_sids(sids))
        return results

    def _target_trustees_ldap3(self, sam: str) -> list[dict]:
        import ldap3
        from impacket.ldap.ldaptypes import LDAP_SID

        entries = self._search_ldap3(
            self._base_dn,
            f"(&(objectClass=user)(sAMAccountName={_ldap_escape(sam)}))",
            ["distinguishedName", "objectSid", "cn", "sAMAccountName"],
        )
        if not entries:
            logger.warning("Failed to find target user %s in domain", sam)
            return [{"display_name": sam, "sid": "", "target": True}]

        entry = entries[0]
        user_dn = str(entry.distinguishedName) if hasattr(entry, "distinguishedName") else ""
        user_cn = str(entry.cn) if hasattr(entry, "cn") else sam
        user_sid = ""
        if hasattr(entry, "objectSid") and entry.objectSid.value:
            try:
                raw = entry.objectSid.value
                user_sid = LDAP_SID(data=bytes(raw)).formatCanonical()
            except Exception:
                user_sid = str(entry.objectSid)
        results = [{"display_name": user_cn, "sid": user_sid, "target": True}]
        if not user_dn:
            return results

        try:
            self._connection.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["tokenGroups"],
            )
        except Exception as e:
            logger.debug("tokenGroups query failed: %s", e)
            return results

        sids: list[str] = []
        for tg in self._connection.entries:
            if hasattr(tg, "tokenGroups") and tg.tokenGroups.value:
                vals = tg.tokenGroups.value
                if not isinstance(vals, list):
                    vals = [vals]
                for val in vals:
                    try:
                        sids.append(LDAP_SID(data=bytes(val)).formatCanonical())
                    except Exception:
                        pass
        results.extend(self._resolve_group_sids(sids))
        return results

    def _resolve_group_sids(self, sids: list[str]) -> list[dict]:
        """Best-effort SID → name. Unknown SIDs are still returned as targets."""
        out: list[dict] = []
        remaining = list(sids)
        # Resolve in chunks to keep filters short
        while remaining:
            chunk = remaining[:20]
            remaining = remaining[20:]
            filt = "(|" + "".join(f"(objectSid={sid})" for sid in chunk) + ")"
            names: dict[str, str] = {}
            try:
                if self._backend == "impacket":
                    from impacket.ldap import ldapasn1
                    from impacket.ldap.ldaptypes import LDAP_SID
                    resp = self._search_impacket(
                        self._base_dn, filt, ["objectSid", "sAMAccountName", "cn"],
                    )
                    for item in resp:
                        if not isinstance(item, ldapasn1.SearchResultEntry):
                            continue
                        sid = cn = ""
                        for attr in item["attributes"]:
                            n = str(attr["type"])
                            if not attr["vals"]:
                                continue
                            if n == "cn":
                                cn = str(attr["vals"][0])
                            elif n == "sAMAccountName" and not cn:
                                cn = str(attr["vals"][0])
                            elif n == "objectSid":
                                sid = LDAP_SID(data=bytes(attr["vals"][0])).formatCanonical()
                        if sid:
                            names[sid] = cn or sid
                else:
                    entries = self._search_ldap3(
                        self._base_dn, filt, ["objectSid", "sAMAccountName", "cn"],
                    )
                    for entry in entries:
                        cn = str(entry.cn) if hasattr(entry, "cn") else ""
                        sid = ""
                        if hasattr(entry, "objectSid") and entry.objectSid.value:
                            try:
                                from impacket.ldap.ldaptypes import LDAP_SID
                                sid = LDAP_SID(data=bytes(entry.objectSid.value)).formatCanonical()
                            except Exception:
                                sid = str(entry.objectSid)
                        if sid:
                            names[sid] = cn or sid
            except Exception as e:
                logger.debug("SID resolve failed: %s", e)
            for sid in chunk:
                out.append({
                    "display_name": names.get(sid, sid),
                    "sid": sid,
                    "target": True,
                })
        return out

    def enumerate_wmi_filters(self, gpos: list[GPO]) -> None:
        """Fill wmi_filter_name / wmi_filter_query from msWMI-Som objects."""
        dns = [g.attributes.wmi_filter_dn for g in gpos if g.attributes.wmi_filter_dn]
        if not dns or not self._connection:
            return
        by_dn = {dn.lower(): [] for dn in dns}
        for gpo in gpos:
            dn = gpo.attributes.wmi_filter_dn
            if dn:
                by_dn.setdefault(dn.lower(), []).append(gpo)

        for dn in list(by_dn):
            try:
                name, query = self._read_wmi_filter(dn)
            except Exception as e:
                logger.debug("WMI filter %s: %s", dn, e)
                continue
            for gpo in by_dn[dn]:
                gpo.attributes.wmi_filter_name = name
                gpo.attributes.wmi_filter_query = query

    def _read_wmi_filter(self, dn: str) -> tuple[str, str]:
        if self._backend == "impacket":
            from impacket.ldap import ldapasn1
            from impacket.ldap.ldapasn1 import Scope
            resp = self._connection.search(
                searchBase=dn,
                searchFilter="(objectClass=msWMI-Som)",
                scope=Scope("baseObject"),
                attributes=["msWMI-Name", "msWMI-Parm1", "displayName"],
            )
            name = query = ""
            for item in resp:
                if not isinstance(item, ldapasn1.SearchResultEntry):
                    continue
                for attr in item["attributes"]:
                    n = str(attr["type"])
                    if not attr["vals"]:
                        continue
                    if n in ("msWMI-Name", "displayName") and not name:
                        name = str(attr["vals"][0])
                    elif n == "msWMI-Parm1":
                        query = str(attr["vals"][0])
            return name, query

        import ldap3
        self._connection.search(
            search_base=dn,
            search_filter="(objectClass=msWMI-Som)",
            search_scope=ldap3.BASE,
            attributes=["msWMI-Name", "msWMI-Parm1", "displayName"],
        )
        name = query = ""
        for entry in self._connection.entries:
            attrs = entry.entry_attributes_as_dict
            raw_name = attrs.get("msWMI-Name") or attrs.get("displayName")
            raw_query = attrs.get("msWMI-Parm1")
            if isinstance(raw_name, list):
                raw_name = raw_name[0] if raw_name else ""
            if isinstance(raw_query, list):
                raw_query = raw_query[0] if raw_query else ""
            name = str(raw_name or "")
            query = str(raw_query or "")
        return name, query

    def close(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            try:
                if self._backend == "impacket":
                    self._connection.close()
                else:
                    self._connection.unbind()
            except Exception:
                pass
            self._connection = None


def _ldap_escape(value: str) -> str:
    """Escape LDAP filter special characters."""
    return (
        value.replace("\\", r"\5c")
        .replace("*", r"\2a")
        .replace("(", r"\28")
        .replace(")", r"\29")
        .replace("\x00", r"\00")
    )


def _wmi_filter_dn(raw: str) -> str:
    """Extract the WMI filter DN from gPCWQLFilter ([LDAP://DN;flag])."""
    if not raw:
        return ""
    text = raw.strip().strip("[]")
    if text.upper().startswith("LDAP://"):
        text = text[7:]
    elif text.upper().startswith("LDAP:"):
        text = text[5:]
    text = text.lstrip("/")
    if ";" in text:
        text = text.split(";", 1)[0]
    return text.strip()


def _parse_ldap_timestamp(val: str):
    """Parse LDAP generalized time format (20240101120000.0Z)."""
    from datetime import datetime
    try:
        # Strip sub-second and timezone
        clean = val.split(".")[0].replace("Z", "")
        return datetime.strptime(clean, "%Y%m%d%H%M%S")
    except Exception:
        return None
