"""Analyser for System Access (password/lockout policy) settings."""

from __future__ import annotations

from ...models.enums import Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import SystemAccessSetting
from ...options import AssessmentOptions
from ..analyser import Analyser

# Matches C# SystemAccessAnalyser exactly
_SETTINGS: dict[str, dict] = {
    "MinimumPasswordAge": {
        "default": "1",
        "reason": "Non-default minimum password age.",
        "detail_fmt": "Minimum password age is {value} days.",
        "triage": Triage.GREEN,
    },
    "MaximumPasswordAge": {
        "default": "42",
        "reason": "Non-default maximum password age.",
        "detail_fmt": "Maximum password age is {value} days.",
        "triage": Triage.GREEN,
    },
    "MinimumPasswordLength": {
        "default": "7",
        "reason": "Non-default minimum password length.",
        "detail_fmt": "Minimum password length is {value} days.",  # C# bug: says "days"
        "triage": Triage.GREEN,
    },
    "PasswordComplexity": {
        "default": "1",
        "reason": "Password complexity disabled.",
        "detail_fmt": "",
        "triage": Triage.YELLOW,
        "only_if": "0",
    },
    "PasswordHistorySize": {
        "default": "24",
        "reason": "Non-default password history size.",
        "detail_fmt": "Password history value is {value}",
        "triage": Triage.GREEN,
    },
    "LockoutBadCount": {
        "default": "5",
        "reason": "Non-default lockout count value.",
        "detail_fmt": "Accounts lock out after {value} bad passwords",
        "triage": Triage.GREEN,
    },
    "ResetLockoutCount": {
        "default": "30",
        "reason": "Non-default lockout reset time value.",
        "detail_fmt": "Invalid attempt counter resets after{value} minutes.",  # C# missing space
        "triage": Triage.GREEN,
    },
    "LockoutDuration": {
        "default": "30",
        "reason": "Non-default lockout duration value.",
        "detail_fmt": "Account unlocks after{value} minutes.",  # C# missing space
        "triage": Triage.GREEN,
    },
    "ForceLogoffWhenHourExpire": {
        "default": "0",
        "reason": "Force logoff outside hours is enforced.",
        "detail_fmt": "",
        "triage": Triage.GREEN,
    },
    "NewAdministratorName": {
        "default": None,  # any value is interesting
        "reason": "Local Administrator account name changed.",
        "detail_fmt": "New local Administrator account name is {value}",
        "triage": Triage.GREEN,
    },
    "NewGuestName": {
        "default": None,
        "reason": "Local Guest account name changed.",
        "detail_fmt": "New local Guest account name is {value}",
        "triage": Triage.GREEN,
    },
    "ClearTextPassword": {
        "default": "0",
        "reason": "SAM (or domain if this GPO applies to DCs) passwords stored with reversible encryption.",
        "detail_fmt": "",
        "triage": Triage.YELLOW,
    },
    "EnableGuestAccount": {
        "default": "0",
        "reason": "Local Guest account enabled.",
        "detail_fmt": "",
        "triage": Triage.YELLOW,
    },
    "EnableAdminAccount": {
        "default": "1",
        "reason": "Local Administrator account disabled.",
        "detail_fmt": "",
        "triage": Triage.GREEN,
    },
    "RequireLogonToChangePassword": {
        "default": "1",
        "reason": "Expired passwords require admin intervention to reset.",
        "detail_fmt": "",
        "triage": Triage.GREEN,
    },
    "LSAAnonymousNameLookup": {
        "default": "0",
        "reason": "Anonymous users can query the local LSA policy.",
        "detail_fmt": "",
        "triage": Triage.GREEN,
    },
}


class SystemAccessAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: SystemAccessSetting = self.setting

        name = setting.setting_name
        value = setting.value_string.strip().strip('"')

        config = _SETTINGS.get(name)
        if not config:
            return self.result

        default = config["default"]

        # "only_if" means only report if value equals this specific value
        only_if = config.get("only_if")
        if only_if is not None:
            if value != only_if:
                return self.result

        # For settings with no default (NewAdministratorName, NewGuestName),
        # any value is interesting
        if default is None:
            if value:
                detail = config["detail_fmt"].format(value=value) if config["detail_fmt"] else ""
                self.add_finding(GpoFinding(
                    finding_reason=config["reason"],
                    finding_detail=detail,
                    triage=config["triage"],
                ))
            return self.result

        # For settings with a default, report if non-default
        if value != default:
            detail = config["detail_fmt"].format(value=value) if config["detail_fmt"] else ""
            self.add_finding(GpoFinding(
                finding_reason=config["reason"],
                finding_detail=detail,
                triage=config["triage"],
            ))

        return self.result
