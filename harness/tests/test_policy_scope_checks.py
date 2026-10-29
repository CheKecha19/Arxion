"""Synthetic acceptance for CHECKS-003/005 profiles, evidence and replay."""

import json

import pytest
from PySide6.QtWidgets import QApplication
from test_policy_exposure import AT, context, rule, selector

from firewall_compliance.analysis.policy_checks import PolicyCheckContext
from firewall_compliance.analysis.policy_scope import ExcessiveAccessCheck, PolicyAttachmentCheck
from firewall_compliance.application.analysis_result import (
    PolicyAnalysisOptions,
    PolicyComponent,
    replay_policy,
)
from firewall_compliance.application.firewall_assurance import build_source_revision
from firewall_compliance.domain.assurance import CheckStatus
from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.policy_attachment import PolicyAttachment
from firewall_compliance.domain.policy_scope import (
    PolicyScopeProfile,
    RequiredPolicyAttachment,
    RoleAccessRequirement,
)
from firewall_compliance.domain.revision import DeviceRevision
from firewall_compliance.domain.source import SourceLocation
from firewall_compliance.interfaces.desktop.policy_scope_settings import PolicyScopeSettings
from firewall_compliance.parsers import ParseRequest, ParserRegistry, SourceDocument
from firewall_compliance.parsers.hp_aruba import HpArubaParser

APP = None


def codes(result):
    return {value.code for value in result.limitations}


def with_parse(base, *, rules=None, attachments=()):
    parsed = base.revision.parse_result
    selected = tuple(rules if rules is not None else parsed.rules)
    source_map = {value.rule_id: value.source_location for value in selected}
    source_map.update({value.attachment_id: value.source_location for value in attachments})
    replaced = ParseResult.model_validate(
        {
            **parsed.model_dump(mode="python"),
            "rules": selected,
            "policy_attachments": attachments,
            "source_map": source_map,
        }
    )
    return base.__class__(
        base.revision.model_copy(update={"parse_result": replaced}), base.analyzed_at
    )


def scope_profile(**changes):
    values = {
        "excessive_access_enabled": True,
        "max_source_addresses": 256,
        "max_destination_addresses": 256,
        "max_destination_ports": 100,
        "role_requirements": (),
        "attachment_inventory_complete": True,
        "required_attachments": (),
    }
    values.update(changes)
    return PolicyScopeProfile(**values)


def test_unknown_profiles_do_not_claim_negative_results():
    base = context(rule())
    excessive = ExcessiveAccessCheck().evaluate(base)
    attachment = PolicyAttachmentCheck().evaluate(base)
    assert excessive.status == CheckStatus.PARTIAL and not excessive.findings
    assert {"EXCESSIVE_THRESHOLDS_UNKNOWN", "ROLE_ACCESS_POLICY_UNKNOWN"} <= codes(excessive)
    assert attachment.status == CheckStatus.PARTIAL and not attachment.findings
    assert {"ATTACHMENT_INVENTORY_UNKNOWN", "REQUIRED_FILTERING_UNKNOWN"} <= codes(attachment)


def test_explicitly_disabled_empty_policies_are_not_applicable():
    profile = PolicyScopeProfile(
        excessive_access_enabled=False,
        role_requirements=(),
        attachment_inventory_complete=False,
        required_attachments=(),
    )
    base = context(rule())
    assert ExcessiveAccessCheck(profile).evaluate(base).status == CheckStatus.NOT_APPLICABLE
    assert PolicyAttachmentCheck(profile).evaluate(base).status == CheckStatus.NOT_APPLICABLE


def test_threshold_finding_has_exact_counts_profile_and_source():
    base = context(rule(source="10.0.0.0/24", destination="192.0.2.0/24", start=1, end=200))
    result = ExcessiveAccessCheck(scope_profile()).evaluate(base)
    assert result.status == CheckStatus.COMPLETE and len(result.findings) == 1
    finding = result.findings[0]
    assert finding.evidence.facts["violations"] == {"destination_ports": 200}
    assert finding.evidence.facts["thresholds"]["destination_ports"] == 100
    assert finding.evidence.source_locations == (
        base.revision.parse_result.rules[0].source_location,
    )


def test_role_requirement_accepts_subset_and_finds_source_or_service_excess():
    requirement = RoleAccessRequirement(
        requirement_id="database-role",
        role_id="database",
        destination_networks=("192.0.2.0/24",),
        approved_source_networks=("10.0.0.0/8",),
        approved_services=(selector("database-tls", start=443, end=443),),
    )
    profile = scope_profile(
        excessive_access_enabled=False,
        max_source_addresses=None,
        max_destination_addresses=None,
        max_destination_ports=None,
        role_requirements=(requirement,),
    )
    good = context(rule(source="10.1.0.0/24", destination="192.0.2.10/32", start=443, end=443))
    bad = context(rule(source="any", destination="192.0.2.10/32", start=1, end=443))
    assert not ExcessiveAccessCheck(profile).evaluate(good).findings
    finding = ExcessiveAccessCheck(profile).evaluate(bad).findings[0]
    assert finding.evidence.facts["source_within_policy"] is False
    assert finding.evidence.facts["service_within_policy"] is False
    assert finding.evidence.facts["requirement"]["role_id"] == "database"


def test_explicit_rule_exception_is_visible_in_profile_and_suppresses_finding():
    profile = scope_profile(exception_rule_ids=("r1",))
    assert not ExcessiveAccessCheck(profile).evaluate(context(rule(start=1, end=500))).findings
    assert profile.exception_rule_ids == ("r1",)


def attachment(identifier, policy_id="EDGE", *, subject="role", interface=False):
    return PolicyAttachment(
        attachment_id=identifier,
        policy_id=policy_id,
        subject_kind="interface" if interface else "user_role",
        subject_id=subject,
        direction="in" if interface else None,
        source_location=SourceLocation(
            source_name="synthetic", object_path=f"$.bindings.{identifier}"
        ),
    )


def test_unbound_policy_requires_explicit_complete_inventory():
    policy_rule = rule(policy_id="EDGE", policy_direction="in")
    base = with_parse(context(policy_rule), rules=(policy_rule,))
    complete = PolicyAttachmentCheck(scope_profile()).evaluate(base)
    incomplete = PolicyAttachmentCheck(
        scope_profile(attachment_inventory_complete=False, required_attachments=None)
    ).evaluate(base)
    assert len(complete.findings) == 1
    assert complete.findings[0].evidence.facts["policy_id"] == "EDGE"
    assert not incomplete.findings
    assert "ATTACHMENT_INVENTORY_INCOMPLETE" in codes(incomplete)


def test_required_interface_direction_and_allowed_policy_are_exact():
    requirement = RequiredPolicyAttachment(
        requirement_id="outside-ingress",
        subject_kind="interface",
        subject_id="outside",
        direction="in",
        allowed_policy_ids=("EDGE",),
    )
    profile = scope_profile(required_attachments=(requirement,))
    policy_rule = rule(policy_id="EDGE", policy_direction="in")
    missing = with_parse(context(policy_rule), rules=(policy_rule,))
    attached = attachment("binding-1", subject="outside", interface=True)
    present = with_parse(context(policy_rule), rules=(policy_rule,), attachments=(attached,))
    assert {
        value.evidence.facts["basis"]
        for value in PolicyAttachmentCheck(profile).evaluate(missing).findings
    } == {
        "complete_attachment_inventory",
        "required_policy_attachment",
    }
    assert not PolicyAttachmentCheck(profile).evaluate(present).findings


def test_user_role_attachment_keeps_legacy_json_without_null_direction():
    value = attachment("role-1")
    assert "direction" not in value.model_dump(mode="json")
    assert PolicyAttachment.model_validate_json(value.model_dump_json()) == value


def test_analysis_result_replays_both_checks_from_frozen_profile():
    policy_rule = rule(policy_id="EDGE", policy_direction="in", start=1, end=200)
    revision = context(policy_rule).revision
    profile = scope_profile()
    options = PolicyAnalysisOptions(
        check_ids=("FW-EXCESSIVE-ACCESS", "FW-ACL-ATTACHMENT"), scope_profile=profile
    )
    component = PolicyComponent(
        component_id="scope",
        revision=revision,
        options=options,
        result=replay_policy(revision, options, AT),
    )
    assert [value.check_id for value in component.result.checks] == list(options.check_ids)
    assert PolicyComponent.model_validate_json(component.model_dump_json()) == component


@pytest.fixture
def settings():
    global APP
    APP = QApplication.instance() or QApplication([])
    widget = PolicyScopeSettings()
    try:
        yield widget
    finally:
        widget.close()


def test_qt_settings_roundtrip_keeps_unknown_complete_and_structured_requirements(settings):
    profile = scope_profile(
        role_requirements=(
            RoleAccessRequirement(
                requirement_id="database",
                role_id="database",
                destination_networks=("192.0.2.0/24",),
                approved_source_networks=("10.0.0.0/8",),
                approved_services=(selector("tls", start=443, end=443),),
            ),
        ),
        required_attachments=(
            RequiredPolicyAttachment(
                requirement_id="outside",
                subject_kind="interface",
                subject_id="outside",
                direction="in",
            ),
        ),
    )
    settings.load_profile(profile.model_dump(mode="json"))
    assert settings.profile() == profile
    settings.role_requirements.setPlainText(json.dumps([]))
    assert settings.profile().role_requirements == ()


def test_hp_aruba_interface_binding_populates_typed_attachment_for_check_005():
    content = (
        b"!Version ArubaOS-CX FL.10.13.1000\n"
        b"access-list ip EDGE\n 10 permit tcp any any eq 443\n!\n"
        b"interface 1/1/1\n apply access-list ip EDGE in\n"
    )
    source = SourceDocument(source_name="synthetic.cfg", content=content, captured_at=AT)
    parsed = HpArubaParser().parse(ParseRequest(source=source, imported_at=AT))
    assert isinstance(parsed, ParseResult)
    attachment = parsed.policy_attachments[0]
    assert attachment.subject_id == "interface:1/1/1" and attachment.direction == "in"
    assert attachment.policy_id == parsed.rules[0].policy_id
    revision = build_source_revision(source, ParserRegistry((HpArubaParser(),)), imported_at=AT)
    assert isinstance(revision, DeviceRevision)
    requirement = RequiredPolicyAttachment(
        requirement_id="edge-in",
        subject_kind="interface",
        subject_id="interface:1/1/1",
        direction="in",
        allowed_policy_ids=(attachment.policy_id,),
    )
    result = PolicyAttachmentCheck(scope_profile(required_attachments=(requirement,))).evaluate(
        PolicyCheckContext(revision, AT)
    )
    assert not result.findings
