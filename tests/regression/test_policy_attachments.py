"""Declared role associations retain source anchors without changing legacy JSON."""

import pytest
from pydantic import ValidationError

from firewall_compliance.domain.parse_result import ParseResult
from firewall_compliance.domain.policy_attachment import PolicyAttachment
from firewall_compliance.domain.source import SourceLocation
from tests.regression.test_analysis_result import policy


def attachment_data():
    original = policy().revision.parse_result
    location = SourceLocation(source_name=original.configuration.source_name, line_start=40)
    attachment = PolicyAttachment(
        attachment_id="attachment:synthetic-role-acl",
        policy_id="controller-session:SYNTHETIC",
        subject_id="SYNTHETIC-ROLE",
        declaration_position=2,
        scope_reference="ap-group:SYNTHETIC",
        source_location=location,
    )
    payload = original.model_dump(mode="python")
    payload["policy_attachments"] = (attachment,)
    payload["source_map"][attachment.attachment_id] = location
    return original, attachment, payload


def test_absent_associations_do_not_add_fields_to_existing_parser_json():
    original = policy().revision.parse_result
    payload = original.model_dump(mode="json")
    assert "policy_attachments" not in payload
    assert (
        ParseResult.model_validate_json(original.model_dump_json()).model_dump(mode="json")
        == payload
    )


def test_association_roundtrips_without_inventing_effective_policy_order():
    _, attachment, payload = attachment_data()
    parsed = ParseResult.model_validate(payload)
    stored = ParseResult.model_validate_json(parsed.model_dump_json())
    assert stored.policy_attachments == (attachment,)
    assert stored.source_map[attachment.attachment_id] == attachment.source_location
    assert "effective_order" not in attachment.model_dump()
    assert "direction" not in attachment.model_dump()


@pytest.mark.parametrize("change", ["duplicate", "missing", "foreign_source", "rule_collision"])
def test_associations_require_unique_exact_source_map_identity(change):
    original, attachment, payload = attachment_data()
    if change == "duplicate":
        payload["policy_attachments"] = (attachment, attachment)
    elif change == "missing":
        payload["source_map"].pop(attachment.attachment_id)
    elif change == "foreign_source":
        foreign = SourceLocation(source_name="foreign.cfg", line_start=40)
        payload["policy_attachments"] = (
            attachment.model_copy(update={"source_location": foreign}),
        )
        payload["source_map"][attachment.attachment_id] = foreign
    else:
        rule = original.rules[0]
        payload["policy_attachments"] = (
            attachment.model_copy(
                update={"attachment_id": rule.rule_id, "source_location": rule.source_location}
            ),
        )
    with pytest.raises(ValidationError):
        ParseResult.model_validate(payload)


def test_associations_are_deeply_frozen_with_the_captured_revision():
    _, _, payload = attachment_data()
    parsed = ParseResult.model_validate(payload)
    captured = policy().revision.model_copy(update={"parse_result": parsed})
    with pytest.raises(TypeError):
        captured.parse_result.policy_attachments[0].subject_id = "ALTERED"
    parsed.policy_attachments[0].subject_id = "CHANGED ORIGINAL BUILDER"
    assert captured.parse_result.policy_attachments[0].subject_id == "SYNTHETIC-ROLE"
