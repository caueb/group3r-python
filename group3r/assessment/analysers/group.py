"""Analyser for Group Membership settings."""

from __future__ import annotations

from ...models.enums import SettingAction, Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import GroupSetting
from ...options import AssessmentOptions
from ..analyser import Analyser

# Well-known high-privilege group SIDs (RID suffixes)
HIGH_PRIV_GROUPS = {
    "544": "Administrators",
    "512": "Domain Admins",
    "519": "Enterprise Admins",
    "518": "Schema Admins",
    "516": "Domain Controllers",
    "498": "Enterprise Read-only Domain Controllers",
    "500": "Administrator",
}

HIGH_PRIV_GROUP_NAMES = {
    "administrators", "domain admins", "enterprise admins",
    "schema admins", "domain controllers", "administrator",
}


class GroupAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: GroupSetting = self.setting

        group_name = setting.name or ""
        group_sid = setting.group_sid or ""

        # Check if this is a high-privilege group
        is_high_priv_group = group_name.lower() in HIGH_PRIV_GROUP_NAMES
        if not is_high_priv_group and group_sid:
            rid = group_sid.rsplit("-", 1)[-1] if "-" in group_sid else ""
            is_high_priv_group = rid in HIGH_PRIV_GROUPS

        if not is_high_priv_group:
            return self.result

        # Check for group renaming
        if setting.new_name:
            self.add_finding(GpoFinding(
                finding_reason="A privileged local group is being renamed.",
                finding_detail=f"Group {group_name} is being renamed to {setting.new_name}",
                triage=Triage.GREEN,
            ))

        # Only process Add/Update/Create actions (not Remove)
        if setting.action not in (SettingAction.ADD, SettingAction.UPDATE, SettingAction.CREATE):
            return self.result

        # Skip if delete flags are set
        if setting.delete_all_groups or setting.delete_all_users or setting.remove_accounts:
            return self.result

        # Check members being added
        for member in setting.members:
            member_name = member.name or member.sid or "Unknown"
            member_sid = member.sid or ""

            # Check if member is a low-priv entity
            is_low_priv = False
            for to in options.trustee_options:
                if to.get("low_priv", False):
                    if (to.get("display_name", "").lower() == member_name.lower() or
                            (member_sid and to.get("sid", "").lower() == member_sid.lower())):
                        is_low_priv = True
                        break

            if is_low_priv:
                self.add_finding(GpoFinding(
                    finding_reason="A privileged local group is having a low-priv member added to it.",
                    finding_detail=f"Group {group_name} is having {member_name} added to it.",
                    triage=Triage.RED,
                ))
            else:
                self.add_finding(GpoFinding(
                    finding_reason="A privileged local group is having a member added to it. Might be interesting, hard to say.",
                    finding_detail=f"Group {group_name} is having {member_name} added to it.",
                    triage=Triage.GREEN,
                ))

        return self.result
