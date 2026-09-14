"""Analyser for Registry settings."""

from __future__ import annotations

import logging

from ...models.enums import InterestingIf, RegKeyValType, Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import RegistrySetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..trustee_match import match_trustee

logger = logging.getLogger(__name__)

# Rights that indicate key write access (YELLOW)
_KEY_WRITE_RIGHTS = {"KEY_WRITE", "KEY_ALL", "WRITE_DAC", "WRITE_OWNER", "SET_VALUE",
                     "CREATE_SUB_KEY", "CREATE_LINK"}

# Rights that indicate key modify/full access (YELLOW in C# for low-priv KEY_ALL/KEY_WRITE)
_KEY_MODIFY_RIGHTS = {"GENERIC_ALL", "GENERIC_WRITE", "ALL_ACCESS",
                      "STANDARD_RIGHTS_ALL", "FILE_ALL", "KEY_ALL", "KEY_WRITE"}


def _as_interesting_if(raw) -> str:
    """Normalise InterestingIf enum or string to the C# enum name."""
    if raw is None:
        return ""
    if isinstance(raw, InterestingIf):
        return raw.value
    return str(getattr(raw, "value", raw))


def _as_triage(raw) -> Triage:
    if isinstance(raw, Triage):
        return raw
    try:
        return Triage(raw)
    except (ValueError, TypeError):
        return Triage.GREEN


class RegistryAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: RegistrySetting = self.setting

        if setting.key_sddl_string:
            self._analyse_key_acl(setting, options)

        setting_key = (setting.key or "").lower()
        for reg_key_rule in options.reg_keys:
            rule_key = (reg_key_rule.get("key") or "")
            if not rule_key or rule_key.lower() not in setting_key:
                continue

            rule_value_name = reg_key_rule.get("value_name") or ""
            interesting_if = _as_interesting_if(reg_key_rule.get("interesting_if", ""))
            rule_triage = _as_triage(reg_key_rule.get("triage", 0))

            values = setting.values or []
            if not values and interesting_if == InterestingIf.PRESENT.value:
                # Key presence with no values (C# still needs a Values loop)
                continue

            present_emitted = False
            for value in values:
                if rule_value_name:
                    vn = (value.value_name or "").lower()
                    if rule_value_name.lower() not in vn:
                        continue

                if interesting_if == InterestingIf.PRESENT.value:
                    if not rule_value_name:
                        token = (setting.source, rule_key.lower())
                        seen = getattr(options, "_reg_present_seen", None)
                        if seen is None:
                            seen = set()
                            options._reg_present_seen = seen
                        if token in seen:
                            continue
                        seen.add(token)
                    elif present_emitted:
                        continue
                    self._check_present(setting, value, reg_key_rule, rule_triage)
                    present_emitted = True
                elif interesting_if == InterestingIf.BAD.value:
                    self._check_bad(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == InterestingIf.NOT_DEFAULT.value:
                    self._check_not_default(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == InterestingIf.NOT_GOOD.value:
                    self._check_not_good(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == InterestingIf.LESS_THAN_GOOD.value:
                    self._check_less_than_good(setting, value, reg_key_rule, rule_triage)

        return self.result

    def _analyse_key_acl(self, setting: RegistrySetting, options: AssessmentOptions) -> None:
        """Analyse registry key SDDL ACLs."""
        from ...sddl.parser import SddlDescriptor
        from ...sddl.constants import SecurableObjectType
        from ..sddl_analyser import analyse_sddl

        try:
            sddl = SddlDescriptor(setting.key_sddl_string, SecurableObjectType.REGISTRY_KEY)
            aces = analyse_sddl(sddl)

            for ace in aces:
                if ace.ace_type != "Allow":
                    continue

                has_write = any(r in _KEY_WRITE_RIGHTS for r in ace.rights)
                has_modify = any(r in _KEY_MODIFY_RIGHTS for r in ace.rights)
                is_owner = "Owner" in ace.rights

                if not has_write and not has_modify and not is_owner:
                    continue

                to = match_trustee(options, ace.trustee, ace.trustee_sid)
                if not to:
                    continue
                if to.get("high_priv", False):
                    continue

                detail = "You'll need to take a closer look at this key to know if this has any value at all. Good luck."
                trustee_name = to.get("display_name") or ace.trustee

                if is_owner:
                    self.add_finding(GpoFinding(
                        finding_reason=f"The {trustee_name} trustee has been made owner of this registry key.",
                        finding_detail=detail,
                        triage=Triage.GREEN,
                        acl_result=[ace],
                    ))
                elif to.get("low_priv", False) and has_modify:
                    self.add_finding(GpoFinding(
                        finding_reason=f"The {trustee_name} trustee has been granted rights to modify this registry key.",
                        finding_detail=detail,
                        triage=Triage.YELLOW,
                        acl_result=[ace],
                    ))
                elif to.get("low_priv", False) or to.get("target", False):
                    self.add_finding(GpoFinding(
                        finding_reason=f"The {trustee_name} trustee has been granted additional rights over this registry key.",
                        finding_detail=detail,
                        triage=Triage.GREEN,
                        acl_result=[ace],
                    ))
        except Exception as e:
            logger.debug("Failed to parse registry key SDDL: %s", e)

    def _rule_detail(self, rule) -> str:
        return f"{rule.get('friendly_description', '')} {rule.get('ms_desc', '')}".strip()

    def _check_present(self, setting, value, rule, triage):
        self.add_finding(GpoFinding(
            finding_reason="This registry key being present at all is considered interesting.",
            finding_detail=self._rule_detail(rule),
            triage=triage,
        ))

    def _check_bad(self, setting, value, rule, triage):
        if self._values_match(value, rule, "bad"):
            self.add_finding(GpoFinding(
                finding_reason="This registry key was found to match a known-vulnerable value.",
                finding_detail=self._rule_detail(rule),
                triage=triage,
            ))

    def _check_not_default(self, setting, value, rule, triage):
        if not self._values_match(value, rule, "default"):
            self.add_finding(GpoFinding(
                finding_reason="This registry key was set to a non-default value, which was interesting enough for me.",
                finding_detail=self._rule_detail(rule),
                triage=triage,
            ))

    def _check_not_good(self, setting, value, rule, triage):
        if not self._values_match(value, rule, "good"):
            self.add_finding(GpoFinding(
                finding_reason="This registry key was set to a non-default value, which was interesting enough for me.",
                finding_detail=self._rule_detail(rule),
                triage=triage,
            ))

    def _check_less_than_good(self, setting, value, rule, triage):
        try:
            current = int(value.value_string) if value.value_string else 0
            good = int(rule.get("good_dword", 0))
            if current < good:
                self.add_finding(GpoFinding(
                    finding_reason="This registry key was set to a 'less-than-good' value, which made it interesting.",
                    finding_detail=self._rule_detail(rule),
                    triage=triage,
                ))
        except (ValueError, TypeError):
            pass

    def _values_match(self, value, rule, prefix: str) -> bool:
        val_type = value.reg_key_val_type

        if val_type == RegKeyValType.REG_DWORD:
            try:
                current = int(value.value_string) if value.value_string else 0
                expected = int(rule.get(f"{prefix}_dword", 0))
                return current == expected
            except (ValueError, TypeError):
                return False
        elif val_type in (RegKeyValType.REG_SZ, RegKeyValType.REG_EXPAND_SZ):
            current = (value.value_string or "").strip()
            expected = (rule.get(f"{prefix}_sz", "") or "").strip()
            return current.lower() == expected.lower()
        elif val_type == RegKeyValType.REG_BINARY:
            current = value.value_bytes or b""
            expected = rule.get(f"{prefix}_binary", b"") or b""
            return current == expected
        return False
