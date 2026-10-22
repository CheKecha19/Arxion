"""Явные synthetic доказательства ACL поверх сетевого pipeline."""

from firewall_compliance.application.device_decision import analyze_imported_device
from firewall_compliance.domain import Protocol, ReachabilityQuery
from firewall_compliance.domain.policy_decision import (
    PolicyBindingEvidence,
    SingleDeviceDecisionResult,
)
from firewall_compliance.domain.source import SourceLocation
from tests.network_import_fixtures import import_scenario

DEVICE_SCENARIOS = ("allow", "no_match", "implicit_deny", "incomplete")


def device_scenario(scenario: str = "allow") -> SingleDeviceDecisionResult:
    imported = import_scenario()
    revision = imported.revision
    configuration = revision.parse_result.configuration
    source = next(
        item for item in revision.sources if item.source_name == configuration.source_name
    )
    query = ReachabilityQuery(
        revision_id=revision.revision_id,
        device_id=revision.device.device_id,
        ingress_interface_id="interface:GigabitEthernet0/1",
        source_ip="10.20.0.10",
        destination_ip="198.51.100.25",
        protocol=Protocol.TCP,
        destination_port=443 if scenario in {"allow", "incomplete"} else 80,
    )
    binding = PolicyBindingEvidence(
        policy_id="INSIDE",
        direction="in",
        interface_id=query.ingress_interface_id,
        interface_label="inside",
        interface_mapping_reference="nameif inside из импортированного документа интерфейсов.",
        source_document_id=source.source_document_id,
        binding_location=SourceLocation(source_name=configuration.source_name, line_start=4),
        complete=scenario != "incomplete",
        completeness_reference="Специально созданная полная ACL INSIDE из POLICY.",
        declaration_origin="synthetic",
        coordinate_space="acl_input",
        implicit_action="deny",
        terminal=scenario == "implicit_deny",
        terminal_reference="В synthetic сценарии явно исключены последующие ACL."
        if scenario == "implicit_deny"
        else None,
    )
    return analyze_imported_device(imported, query, binding)
