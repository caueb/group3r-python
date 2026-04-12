"""Analyser for Registry settings."""

from __future__ import annotations

import logging

from ...models.enums import RegKeyValType, Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import RegistrySetting
from ...options import AssessmentOptions
from ..analyser import Analyser

logger = logging.getLogger(__name__)

# Rights that indicate key write access (YELLOW)
_KEY_WRITE_RIGHTS = {"KEY_WRITE", "KEY_ALL", "WRITE_DAC", "WRITE_OWNER", "SET_VALUE",
                     "CREATE_SUB_KEY", "CREATE_LINK"}

# Rights that indicate key modify/full access (RED)
_KEY_MODIFY_RIGHTS = {"GENERIC_ALL", "GENERIC_WRITE", "ALL_ACCESS",
                      "STANDARD_RIGHTS_ALL", "FILE_ALL"}


class RegistryAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: RegistrySetting = self.setting

        # Check registry key ACLs if present
        if setting.key_sddl_string:
            self._analyse_key_acl(setting, options)

        # Match registry values against assessment rules
        for reg_key_rule in options.reg_keys:
            rule_key = reg_key_rule.get("key", "")
            rule_value_name = reg_key_rule.get("value_name", "")

            # Match key path (case-insensitive)
            if setting.key and rule_key and setting.key.lower() != rule_key.lower():
                continue

            # Check each value in the setting
            for value in setting.values:
                if rule_value_name and value.value_name.lower() != rule_value_name.lower():
                    continue

                interesting_if = reg_key_rule.get("interesting_if", "")
                rule_triage = Triage(reg_key_rule.get("triage", 0))

                if interesting_if == "Present":
                    self._check_present(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == "Bad":
                    self._check_bad(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == "NotDefault":
                    self._check_not_default(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == "NotGood":
                    self._check_not_good(setting, value, reg_key_rule, rule_triage)
                elif interesting_if == "LessThanGood":
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

                # Check for interesting rights
                has_write = any(r in _KEY_WRITE_RIGHTS for r in ace.rights)
                has_modify = any(r in _KEY_MODIFY_RIGHTS for r in ace.rights)
                is_owner = "Owner" in ace.rights

                if not has_write and not has_modify and not is_owner:
                    continue

                # Match against trustee options
                for to in options.trustee_options:
                    matched = (
                        to.get("display_name", "").lower() == ace.trustee.lower() or
                        to.get("sid", "").lower() == ace.trustee.lower()
                    )
                    if not matched:
                        continue

                    if to.get("high_priv", False):
                        break  # Expected, not interesting

                    detail = "You'll need to take a closer look at this key to know if this has any value at all. Good luck."

                    if is_owner:
                        self.add_finding(GpoFinding(
                            finding_reason=f"The {ace.trustee} trustee has been made owner of this registry key.",
                            finding_detail=detail,
                            triage=Triage.GREEN,
                            acl_result=[ace],
                        ))
                        break
                    elif to.get("low_priv", False) and has_modify:
                        self.add_finding(GpoFinding(
                            finding_reason=f"The {ace.trustee} trustee has been granted rights to modify this registry key.",
                            finding_detail=detail,
                            triage=Triage.YELLOW,
                            acl_result=[ace],
                        ))
                        break
                    elif to.get("low_priv", False) or to.get("target", False):
                        self.add_finding(GpoFinding(
                            finding_reason=f"The {ace.trustee} trustee has been granted additional rights over this registry key.",
                            finding_detail=detail,
                            triage=Triage.GREEN,
                            acl_result=[ace],
                        ))
                        break
        except Exception as e:
            logger.debug("Failed to parse registry key SDDL: %s", e)

    def _rule_detail(self, rule) -> str:
        return f"{rule.get('friendly_description', '')} {rule.get('ms_desc', '')}".strip()

    def _check_present(self, setting, value, rule, triage):
        """Value is interesting simply because it exists."""
        self.add_finding(GpoFinding(
            finding_reason="This registry key being present at all is considered interesting.",
            finding_detail=self._rule_detail(rule),
            triage=triage,
        ))

    def _check_bad(self, setting, value, rule, triage):
        """Value matches a known-bad value."""
        if self._values_match(value, rule, "bad"):
            self.add_finding(GpoFinding(
                finding_reason="This registry key was found to match a known-vulnerable value.",
                finding_detail=self._rule_detail(rule),
                triage=triage,
            ))

    def _check_not_default(self, setting, value, rule, triage):
        """Value differs from the default."""
        if not self._values_match(value, rule, "default"):
            self.add_finding(GpoFinding(
                finding_reason="This registry key was set to a non-default value, which was interesting enough for me.",
                finding_detail=self._rule_detail(rule),
                triage=triage,
            ))

    def _check_not_good(self, setting, value, rule, triage):
        """Value is not the recommended good value."""
        if not self._values_match(value, rule, "good"):
            self.add_finding(GpoFinding(
                finding_reason="This registry key was set to a non-default value, which was interesting enough for me.",
                finding_detail=self._rule_detail(rule),
                triage=triage,
            ))

    def _check_less_than_good(self, setting, value, rule, triage):
        """Value is less than the recommended good value (DWORD comparison)."""
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
        """Compare a registry value against a rule's expected value."""
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
