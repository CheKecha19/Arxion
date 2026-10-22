"""Проверки объяснимого сравнения ревизий устройства."""

from uuid import UUID

import pytest
from tests.revision_fixtures import CONFIGURATION_SOURCE_ID, make_revision

from firewall_compliance.analysis import compare_device_revisions
from firewall_compliance.domain import (
    DataOrigin,
    DataStatus,
    RevisionChangeKind,
    RevisionEntityKind,
    Route,
    SourceLocation,
)


def test_identical_content_can_form_two_distinct_revisions() -> None:
    """Историческая идентичность ревизии не выводится из хеша конфигурации."""
    before = make_revision(revision_id=UUID("10000000-0000-0000-0000-000000000001"))
    after = make_revision(revision_id=UUID("10000000-0000-0000-0000-000000000002"))

    assert (
        before.parse_result.configuration.content_sha256
        == after.parse_result.configuration.content_sha256
    )
    assert before.revision_id != after.revision_id


def test_diff_reports_added_removed_and_modified_network_facts() -> None:
    """Diff сохраняет тип изменения и доказательные данные каждого факта."""
    before = make_revision()
    modified_interface = before.interfaces[0].model_copy(update={"zone": "trusted"})
    added_route = Route(
        route_id="route:branch",
        device_id="fixture-device",
        origin=DataOrigin.IMPORTED,
        source_document_id=CONFIGURATION_SOURCE_ID,
        source_location=SourceLocation(source_name="fixture.config", object_path="$.routes[1]"),
        destination="10.10.0.0/16",
        next_hop="10.0.0.254",
        metric=10,
    )
    after = make_revision(
        revision_id=UUID("10000000-0000-0000-0000-000000000002"),
        interfaces=(modified_interface,),
        routes=(added_route,),
        network_segments=(),
        topology_links=(),
        network_segments_status=DataStatus.UNKNOWN,
        topology_status=DataStatus.UNKNOWN,
    )

    diff = compare_device_revisions(before, after)
    changes = {
        (change.entity_kind, change.change_kind, change.entity_id) for change in diff.changes
    }

    assert (
        RevisionEntityKind.INTERFACE,
        RevisionChangeKind.MODIFIED,
        "interface:inside",
    ) in changes
    assert (RevisionEntityKind.ROUTE, RevisionChangeKind.REMOVED, "route:default") in changes
    assert (RevisionEntityKind.ROUTE, RevisionChangeKind.ADDED, "route:branch") in changes
    assert (
        RevisionEntityKind.NETWORK_SEGMENT,
        RevisionChangeKind.REMOVED,
        "segment:inside",
    ) in changes
    assert all(change.evidence.facts for change in diff.changes)


def test_parser_version_change_is_not_device_configuration_change() -> None:
    """Смена нормализации помечается отдельно при неизменном исходном содержимом."""
    before = make_revision()
    after = make_revision(
        revision_id=UUID("10000000-0000-0000-0000-000000000002"),
        parser_version="1.1.0",
    )

    diff = compare_device_revisions(before, after)

    assert diff.normalization_changed is True
    assert all(change.entity_kind != RevisionEntityKind.CONFIGURATION for change in diff.changes)
    assert diff.limitations


def test_diff_rejects_revisions_from_different_devices() -> None:
    """Сравнение не создаёт ложную историю между разными устройствами."""
    with pytest.raises(ValueError, match="одного устройства"):
        compare_device_revisions(make_revision(), make_revision(device_id="another-device"))
