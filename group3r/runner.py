"""Main orchestrator for Group3r analysis pipeline."""

from __future__ import annotations

import logging
import sys
import time
from datetime import datetime, timezone

from .ad.sysvol import load_sysvol_offline
from .assessment.analyser import get_analyser
from .assessment.sddl_analyser import analyse_gpo_acl
from .models.enums import PolicyType, Triage
from .models.findings import GpoResult, SettingResult
from .models.gpo import GPO
from .options import GrouperOptions
from .output.json_printer import gpo_results_to_json
from .output.table_printer import format_gpo_result

logger = logging.getLogger(__name__)

BANNER = r"""
  .,-:::::/ :::::::..       ...      ...    :::::::::::::.  .::.   :::::::..
,;;-'````'  ;;;;``;;;;   .;;;;;;;.   ;;     ;;; `;;;```.;;;;'`';;, ;;;;``;;;;
[[[   [[[[[[/[[[,/[[['  ,[[     \[[,[['     [[[  `]]nnn]]'    .n[[  [[[,/[['
'$$c.    '$$ $$$$$$c    $$$,     $$$$$      $$$   $$$''      ``'$$$ $$$$$$c
 `Y8bo,,,o88o888b '88bo,'888,_ _,88P88    .d888   888o       ,,o888 888b'''8b,
   `'YMUP'YMMMMMM  'W'   'YMMMMMP'  'YmmMMMM''   YMMMb      YMMP'  MMMM   'WM;
                                                    github.com/Group3r/Group3r
                                                            Python Edition

"""


def _status(msg: str) -> None:
    """Print a status message to stderr so it doesn't pollute stdout output."""
    print(msg, file=sys.stderr, flush=True)


def _log_line(tag: str, message: str = "") -> str:
    """Format a log line matching the original Group3r output timestamp format."""
    now = datetime.now(timezone.utc).astimezone()
    offset = now.strftime("%z")
    # Format offset as +HH:MM
    tz_str = f"{offset[:3]}:{offset[3:]}" if len(offset) == 5 else offset
    ts = now.strftime("%Y-%m-%d %H:%M:%S")
    if message:
        return f"{ts} {tz_str} [{tag}] {message}\n"
    return f"{ts} {tz_str} [{tag}] \n"


def run(options: GrouperOptions) -> None:
    """Execute the Group3r analysis pipeline."""
    _status(BANNER)

    # Load GPOs
    gpos: list[GPO] = []

    if options.offline_mode:
        if not options.sysvol_path:
            _status("[!] Offline mode requires a SYSVOL path (-y).")
            sys.exit(1)
        _status(f"[*] Loading SYSVOL offline from: {options.sysvol_path}")
        gpos = load_sysvol_offline(options.sysvol_path)
    else:
        # Online mode - LDAP + SMB
        if not options.target_domain and not options.target_dc:
            _status("[!] Online mode requires a domain (-d) or DC IP (--dc-ip).")
            _status("    Use -o for offline mode with -y for SYSVOL path.")
            sys.exit(1)

        from .ad.active_directory import ActiveDirectory

        target_domain = options.target_domain
        auth_domain = options.auth_domain or target_domain

        _status(f"[*] Target domain: {target_domain}")
        if options.target_dc:
            _status(f"[*] DC IP: {options.target_dc}")
        if auth_domain != target_domain:
            _status(f"[*] Auth domain: {auth_domain} (cross-domain)")
        if options.username:
            _status(f"[*] User: {auth_domain}\\{options.username}")

        if options.verbose:
            logging.getLogger("group3r").setLevel(logging.DEBUG)

        ad = ActiveDirectory(
            target_domain=target_domain,
            dc_ip=options.target_dc,
            dc_host=options.dc_host,
            username=options.username,
            password=options.password,
            hashes=options.hashes,
            use_kerberos=options.use_kerberos,
            auth_domain=auth_domain,
        )
        try:
            _status("[*] Connecting to LDAP...")
            ad.ldap.connect()
            if options.username:
                _status("[*] Resolving current user groups...")
                try:
                    targets = ad.ldap.enumerate_target_trustees(options.username)
                    options.assessment_options.merge_target_trustees(targets)
                    _status(f"[+] {len(targets)} target trustee(s)")
                except Exception as e:
                    _status(f"[!] Target trustee enumeration failed: {e}")
            _status("[*] Enumerating GPOs from LDAP...")
            ldap_gpos = ad.ldap.enumerate_gpos()
            _status(f"[+] Found {len(ldap_gpos)} GPOs in LDAP")

            if ldap_gpos:
                _status("[*] Reading SYSVOL via SMB...")
                try:
                    sysvol_gpos = ad.smb.enumerate_and_parse_sysvol(
                        max_threads=options.max_sysvol_threads,
                    )
                    _status(f"[+] Parsed {len(sysvol_gpos)} GPOs from SYSVOL")

                    # Merge: append SYSVOL settings so LDAP-only settings survive
                    gpo_by_uid: dict[str, GPO] = {}
                    for gpo in ldap_gpos:
                        gpo_by_uid[gpo.attributes.uid.strip("{}").lower()] = gpo
                    for sg in sysvol_gpos:
                        uid = sg.attributes.uid.strip("{}").lower()
                        if uid in gpo_by_uid:
                            gpo_by_uid[uid].settings.extend(sg.settings)
                            gpo_by_uid[uid].gpo_files.extend(sg.gpo_files)
                            if sg.attributes.path_in_sysvol:
                                gpo_by_uid[uid].attributes.path_in_sysvol = (
                                    sg.attributes.path_in_sysvol
                                )
                            if sg.attributes.is_morphed_gpo:
                                gpo_by_uid[uid].attributes.is_morphed_gpo = True
                        else:
                            gpo_by_uid[uid] = sg
                    gpos = list(gpo_by_uid.values())
                except Exception as e:
                    _status(f"[!] SMB SYSVOL read failed: {e}")
                    _status("[*] Returning GPOs with LDAP metadata only.")
                    gpos = ldap_gpos

                # Enumerate GPO links (bulk query for all OUs)
                _status("[*] Enumerating GPO links...")
                try:
                    ad.ldap.enumerate_gpo_links(gpos)
                    linked = sum(1 for g in gpos if g.attributes.gpo_links)
                    _status(f"[+] {linked}/{len(gpos)} GPOs have links")
                except Exception as e:
                    _status(f"[!] GPO link enumeration failed: {e}")

                _status("[*] Enumerating software installation packages...")
                try:
                    ad.ldap.enumerate_gpo_packages(gpos)
                    pkg_count = sum(
                        1 for g in gpos for s in g.settings
                        if type(s).__name__ == "PackageSetting"
                    )
                    _status(f"[+] {pkg_count} package setting(s)")
                except Exception as e:
                    _status(f"[!] Package enumeration failed: {e}")

                try:
                    ad.ldap.enumerate_wmi_filters(gpos)
                except Exception as e:
                    _status(f"[!] WMI filter enumeration failed: {e}")

                from .assessment.path_analyser import PathAnalyser
                options.assessment_options.path_analyser = PathAnalyser(
                    options.assessment_options, ad.smb,
                )
        except Exception as e:
            _status(f"[!] Error: {e}")
            if options.verbose:
                import traceback
                _status(traceback.format_exc())
            sys.exit(1)
        finally:
            ad.cleanup()

    _status(f"[+] {len(gpos)} GPOs loaded.")
    _status("[*] Analysing GPO settings...")

    # Analyse each GPO
    all_results: list[GpoResult] = []
    total_findings = 0
    total_settings = 0

    for gpo in gpos:
        if options.current_only and gpo.attributes.is_morphed_gpo:
            continue

        attrs = gpo.attributes
        if options.enabled_only:
            if not attrs.computer_policy_enabled and not attrs.user_policy_enabled:
                continue
            if not attrs.gpo_links:
                continue
            if not any("Enabled" in (link.link_enforced or "") for link in attrs.gpo_links):
                continue

        result = GpoResult(attributes=attrs)

        if attrs.nt_security_descriptor:
            acl_findings = analyse_gpo_acl(
                attrs.nt_security_descriptor, options.assessment_options
            )
            for finding in acl_findings:
                if finding.triage >= options.min_triage:
                    result.gpo_attribute_findings.append(finding)
                    result.gpo_acl_results.extend(finding.acl_result)
                    total_findings += 1

        for setting in gpo.settings:
            if options.enabled_only:
                if setting.policy_type == PolicyType.COMPUTER and not attrs.computer_policy_enabled:
                    continue
                if setting.policy_type == PolicyType.USER and not attrs.user_policy_enabled:
                    continue

            analyser = get_analyser(setting)
            if analyser is None:
                continue

            analyser.min_triage = options.min_triage
            setting_result = analyser.analyse(options.assessment_options)
            total_settings += 1

            if setting_result.findings or not options.findings_only:
                result.setting_results.append(setting_result)
                total_findings += len(setting_result.findings)

        if options.findings_only and not result.setting_results and not result.gpo_attribute_findings:
            continue

        all_results.append(result)

    _status(f"[+] Analysis complete. {total_findings} finding(s) "
            f"across {total_settings} settings in {len(all_results)} GPOs.")

    # Output results
    if options.json_output:
        json_output = gpo_results_to_json(all_results)
        if options.outfile:
            with open(options.outfile, "w") as f:
                f.write(json_output)
            _status(f"[+] JSON output written to {options.outfile}")
        else:
            sys.stdout.write(json_output)
            sys.stdout.write("\n")
    else:
        def _build_output() -> str:
            parts = []
            parts.append(_log_line("Info", "Parsed args successfully."))
            for result in all_results:
                parts.append(_log_line("GPO"))
                parts.append(format_gpo_result(result, options.findings_only))
            # Convert to CRLF line endings to match original C# Group3r output
            return "".join(parts).replace("\r\n", "\n").replace("\n", "\r\n")

        output = _build_output()
        if options.outfile:
            with open(options.outfile, "wb") as f:
                f.write(output.encode("utf-8"))
            _status(f"[+] Output written to {options.outfile}")
        else:
            sys.stdout.buffer.write(output.encode("utf-8"))
