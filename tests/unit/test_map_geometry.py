"""Crossing and bridge geometry, including endpoints and near-parallel lines."""

from hypothesis import given
from hypothesis import strategies as st

from firewall_compliance.interfaces.desktop.map_geometry import bridge_positions, crossing


def test_bridge_is_only_on_the_upper_edge() -> None:
    segments = [((0.0, 0.0), (100.0, 100.0)), ((0.0, 100.0), (100.0, 0.0))]
    assert bridge_positions(segments) == {1: (0.5,)}


def test_shared_endpoints_parallel_and_collinear_lines_have_no_bridge() -> None:
    assert crossing(((0, 0), (100, 100)), ((100, 100), (200, 0))) is None
    assert crossing(((0, 0), (100, 0)), ((0, 10), (100, 10))) is None
    assert crossing(((0, 0), (100, 0)), ((20, 0), (120, 0))) is None


@given(
    st.floats(min_value=-10000, max_value=10000, allow_nan=False),
    st.floats(min_value=-10000, max_value=10000, allow_nan=False),
)
def test_crossing_is_translation_invariant(x: float, y: float) -> None:
    point = crossing(((x, y), (x + 100, y + 100)), ((x, y + 100), (x + 100, y)))
    assert point is not None
    assert abs(point[0] - 0.5) < 1e-9
