"""Analyser for Group Membership settings."""

from __future__ import annotations

from ...models.enums import SettingAction, Triage
from ...models.findings import GpoFinding, SettingResult
from ...models.settings import GroupSetting
from ...options import AssessmentOptions
from ..analyser import Analyser
from ..trustee_match import is_high_priv, is_low_priv, match_trustee


class GroupAnalyser(Analyser):
    def analyse(self, options: AssessmentOptions) -> SettingResult:
        setting: GroupSetting = self.setting

        group_name = setting.name or ""
        group_sid = setting.group_sid or ""
        group_opt = match_trustee(options, group_name, group_sid)
        group_is_high = bool(group_opt and group_opt.get("high_priv")) or is_high_priv(
            options, group_name, group_sid
        )
        group_display = (group_opt.get("display_name") if group_opt else None) or group_name

        if not group_is_high:
            return self.result

        # Only Add/Update/Create, and not when the setting is a wipe
        if setting.action not in (SettingAction.ADD, SettingAction.UPDATE, SettingAction.CREATE):
            return self.result

        if setting.delete_all_groups or setting.delete_all_users or setting.remove_accounts:
            return self.result

        if setting.new_name:
            self.add_finding(GpoFinding(
                finding_reason="A privileged local group is being renamed.",
                finding_detail=f"Group {group_display} is being renamed to {setting.new_name}",
                triage=Triage.GREEN,
            ))

        for member in setting.members:
            member_name = member.name or member.sid or "Unknown"
            member_sid = member.sid or ""
            member_opt = match_trustee(options, member_name, member_sid)
            member_display = (
                (member_opt.get("display_name") if member_opt else None) or member_name
            )

            if is_low_priv(options, member_name, member_sid):
                self.add_finding(GpoFinding(
                    finding_reason="A privileged local group is having a low-priv member added to it.",
                    finding_detail=f"Group {group_display} is having {member_display} added to it.",
                    triage=Triage.RED,
                ))
            elif not is_high_priv(options, member_name, member_sid):
                self.add_finding(GpoFinding(
                    finding_reason="A privileged local group is having a member added to it. Might be interesting, hard to say.",
                    finding_detail=f"Group {group_display} is having {member_name} added to it.",
                    triage=Triage.GREEN,
                ))

        return self.result
