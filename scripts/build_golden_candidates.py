"""Явная генерация кандидатов эталонов без изменения golden-файлов."""

import argparse
import json
from pathlib import Path

from tests.asa_forwarding_fixtures import SCENARIOS as FORWARDING_SCENARIOS
from tests.device_decision_fixtures import DEVICE_SCENARIOS, device_scenario
from tests.fakes import FixtureParser, make_fixture_request
from tests.forwarding_policy_scenarios import POLICY_SCENARIOS, policy_scenario
from tests.golden.test_asa_forwarding_golden import parse_forwarding_scenario
from tests.golden.test_cisco_asa_golden import parse_fixture
from tests.golden.test_network_import_golden import NETWORK_SCENARIOS
from tests.golden.test_reachability_golden import SCENARIOS, analyze_scenario
from tests.integration.test_firewall_assurance import FIXTURES, analyze_fixture
from tests.network_import_fixtures import import_scenario
from tests.revision_fixtures import make_revision

from firewall_compliance.domain import DataStatus


def main() -> None:
    """Создать JSON-кандидаты, требующие просмотра и отдельного подтверждения."""
    parser = argparse.ArgumentParser(description="Подготовить кандидаты golden-файлов.")
    parser.add_argument("output_directory", type=Path)
    output = parser.parse_args().output_directory
    models = {
        "neutral_parse_result": FixtureParser().parse(make_fixture_request()),
        "cisco_asa_basic_access": parse_fixture("asa_basic_access.cfg"),
        "cisco_asa_objects_and_groups": parse_fixture("asa_objects_and_groups.cfg"),
        "cisco_asa_nat_unsupported": parse_fixture("asa_nat_unsupported.cfg"),
        "device_revision_complete": make_revision(),
        "device_revision_incomplete": make_revision(
            interfaces=(),
            routes=(),
            network_segments=(),
            topology_links=(),
            interfaces_status=DataStatus.UNKNOWN,
            routes_status=DataStatus.UNSUPPORTED,
            network_segments_status=DataStatus.UNKNOWN,
            topology_status=DataStatus.UNKNOWN,
        ),
        "firewall_assurance": analyze_fixture(),
        "firewall_assurance_incomplete": analyze_fixture(
            (FIXTURES / "policy_quality.cfg").read_bytes()
            + b"access-list AUDIT extended permit tcp any any eq 443 time-range WORK\n"
        ),
    }
    models.update(
        {f"reachability_{scenario}": analyze_scenario(scenario) for scenario in SCENARIOS}
    )
    models.update(
        {f"network_import_{scenario}": import_scenario(scenario) for scenario in NETWORK_SCENARIOS}
    )
    output.mkdir(parents=True, exist_ok=True)
    models.update(
        {f"device_decision_{scenario}": device_scenario(scenario) for scenario in DEVICE_SCENARIOS}
    )
    models.update(
        {
            f"asa_forwarding_{scenario}": parse_forwarding_scenario(scenario)
            for scenario in FORWARDING_SCENARIOS
        }
    )
    models.update(
        {
            f"forwarding_policy_{scenario}": policy_scenario(scenario)
            for scenario in POLICY_SCENARIOS
        }
    )
    for name, model in models.items():
        output.joinpath(f"{name}.candidate.json").write_text(
            json.dumps(model.model_dump(mode="json"), ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
