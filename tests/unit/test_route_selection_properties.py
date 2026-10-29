"""Свойства LPM и независимости приоритетов от представления входа."""

from ipaddress import IPv4Network

from hypothesis import given, settings
from hypothesis import strategies as st
from tests.reachability_fixtures import make_query, make_rib_revision, make_route

from firewall_compliance.analysis import select_route


@settings(max_examples=60, deadline=None)
@given(
    prefixes=st.sets(st.integers(min_value=0, max_value=32), min_size=1, max_size=5),
    distance=st.integers(min_value=0, max_value=254),
    metric=st.integers(min_value=0, max_value=100000),
)
def test_lpm_selects_longest_containing_prefix_regardless_of_priority(
    prefixes: set[int],
    distance: int,
    metric: int,
) -> None:
    routes = tuple(
        make_route(
            f"prefix-{prefix}",
            str(IPv4Network(f"198.51.100.25/{prefix}", strict=False)),
            administrative_distance=distance,
            metric=metric,
        )
        for prefix in sorted(prefixes)
    )
    result = select_route(make_rib_revision(routes), make_query())
    assert result.status == "selected"
    assert result.candidate_route_ids == (f"prefix-{max(prefixes)}",)


@settings(max_examples=50, deadline=None)
@given(
    priorities=st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=254),
            st.integers(min_value=0, max_value=1000),
        ),
        min_size=2,
        max_size=5,
    )
)
def test_same_kind_equal_prefix_selection_matches_explicit_numeric_priorities(
    priorities: list[tuple[int, int]],
) -> None:
    routes = tuple(
        make_route(str(index), administrative_distance=ad, metric=metric)
        for index, (ad, metric) in enumerate(priorities)
    )
    expected = tuple(
        str(index) for index, priority in enumerate(priorities) if priority == min(priorities)
    )
    result = select_route(make_rib_revision(routes), make_query())
    assert result.candidate_route_ids == expected
    assert result.status == ("selected" if len(expected) == 1 else "equal_cost")
    reversed_result = select_route(make_rib_revision(tuple(reversed(routes))), make_query())
    assert result.model_dump(mode="json") == reversed_result.model_dump(mode="json")
