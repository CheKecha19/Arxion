"""Golden-проверки детерминированных представлений ревизий устройства."""

from pathlib import Path

from tests.golden.assertions import assert_matches_golden
from tests.revision_fixtures import make_revision

from firewall_compliance.domain import DataStatus

EXPECTED_DIRECTORY = Path(__file__).parent / "expected"


def test_complete_device_revision_matches_golden_file() -> None:
    """Полная ревизия не меняет сериализуемый контракт неявно."""
    assert_matches_golden(make_revision(), EXPECTED_DIRECTORY / "device_revision_complete.json")


def test_incomplete_device_revision_matches_golden_file() -> None:
    """Неполные данные остаются явно помеченными в контракте ревизии."""
    assert_matches_golden(
        make_revision(
            interfaces=(),
            routes=(),
            network_segments=(),
            topology_links=(),
            interfaces_status=DataStatus.UNKNOWN,
            routes_status=DataStatus.UNSUPPORTED,
            network_segments_status=DataStatus.UNKNOWN,
            topology_status=DataStatus.UNKNOWN,
        ),
        EXPECTED_DIRECTORY / "device_revision_incomplete.json",
    )
