"""Сквозная проверка сборки ревизии после парсинга конфигурации."""

from tests.revision_fixtures import make_revision

from firewall_compliance.domain import DataStatus


def test_parse_result_is_embedded_in_revision_with_explicit_data_statuses() -> None:
    """Конфигурация и неполная сетивая информация образуют единый снимок."""
    revision = make_revision(
        interfaces=(),
        routes=(),
        network_segments=(),
        topology_links=(),
        interfaces_status=DataStatus.UNKNOWN,
        routes_status=DataStatus.UNSUPPORTED,
        network_segments_status=DataStatus.UNKNOWN,
        topology_status=DataStatus.UNKNOWN,
    )

    assert revision.parse_result.configuration.device_id == revision.device.device_id
    assert revision.routes_status == DataStatus.UNSUPPORTED
