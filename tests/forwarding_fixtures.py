"""Синтетические факты пересылки без parser/evaluator."""

from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import UUID

from firewall_compliance.domain.configuration import Rule
from firewall_compliance.domain.enums import DataStatus, EndpointKind, Protocol, RuleAction
from firewall_compliance.domain.forwarding import (
    FEATURE_SCOPES,
    FeatureInventory,
    FlowApplicability,
    ForwardingAcl,
    ForwardingBinding,
    ForwardingContext,
    ForwardingInterface,
    ForwardingLocation,
    ForwardingSource,
    ForwardingToggle,
)
from firewall_compliance.domain.network import Endpoint, PortRange, Service
from firewall_compliance.domain.observation import ObservationEvidence
from firewall_compliance.domain.reachability import ReachabilityQuery
from firewall_compliance.domain.source import SourceLocation

REVISION_ID = UUID("00000000-0000-4000-8000-000000000001")
CONFIGURATION_ID = UUID("00000000-0000-4000-8000-000000000002")
CONFIG_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000003")
NAT_SOURCE_ID = UUID("00000000-0000-4000-8000-000000000004")
OBSERVED_AT = datetime(2026, 10, 10, 9, 0, tzinfo=UTC)
CAPTURED_AT = datetime(2026, 10, 10, 9, 1, tzinfo=UTC)
IMPORTED_AT = datetime(2026, 10, 10, 9, 2, tzinfo=UTC)
DEVICE_ID = "synthetic-firewall"
CONFIG_NAME = "synthetic.config"


def forwarding_location(line: int) -> ForwardingLocation:
    return ForwardingLocation(
        source_document_id=CONFIG_SOURCE_ID,
        location=SourceLocation(source_name=CONFIG_NAME, line_start=line),
    )


def forwarding_rule(sequence: int = 10, **changes: Any) -> Rule:
    any_endpoint = Endpoint(endpoint_id="any", name="any", kind=EndpointKind.ANY)
    values = {
        "rule_id": f"ace-{sequence}",
        "configuration_id": CONFIGURATION_ID,
        "name": f"ace-{sequence}",
        "sequence": sequence,
        "action": RuleAction.ALLOW,
        "enabled": True,
        "sources": (any_endpoint,),
        "destinations": (any_endpoint,),
        "services": (
            Service(
                service_id="https",
                name="https",
                protocol=Protocol.TCP,
                port_ranges=(PortRange(start=443, end=443),),
            ),
        ),
        "policy_id": "INSIDE",
        "policy_semantics": "first_match",
        "match_status": DataStatus.KNOWN,
        "source_location": SourceLocation(source_name=CONFIG_NAME, line_start=sequence),
        **changes,
    }
    return Rule.model_validate(values)


def forwarding_flow(protocol: Protocol = Protocol.TCP, **changes: Any) -> FlowApplicability:
    return FlowApplicability.model_validate(
        {
            "query": ReachabilityQuery(
                revision_id=REVISION_ID,
                device_id=DEVICE_ID,
                device_context="synthetic-context",
                ingress_interface_id="inside",
                source_ip="192.0.2.10",
                destination_ip="198.51.100.10",
                protocol=protocol,
                destination_port=None if protocol == Protocol.ICMP else 443,
            ),
            "origin": "synthetic",
            "reference": "Synthetic flow declaration",
            **changes,
        }
    )


def empty_forwarding_context(**changes: Any) -> ForwardingContext:
    return ForwardingContext.model_validate(
        {
            "revision_id": REVISION_ID,
            "configuration_id": CONFIGURATION_ID,
            "device_id": DEVICE_ID,
            "device_context": "synthetic-context",
            "imported_at": IMPORTED_AT,
            **changes,
        }
    )


def make_forwarding_context(**changes: Any) -> ForwardingContext:
    observation = ObservationEvidence(
        observed_at=OBSERVED_AT,
        method="synthetic",
        reference="Synthetic observation",
    )
    common = {
        "device_id": DEVICE_ID,
        "device_context": "synthetic-context",
        "declared_version": "9.16(1)",
        "version_provenance": "documentation",
        "version_reference": "Synthetic version declaration",
        "origin": "synthetic",
        "origin_reference": "Authored contract fixture",
        "captured_at": CAPTURED_AT,
        "observation": observation,
        "selection": "all",
        "extent": "full",
        "encoding": "ascii",
        "capture_success": True,
        "completeness_reference": "Synthetic complete inventory",
    }
    config_scopes = tuple(
        sorted(
            {
                scope
                for scopes in FEATURE_SCOPES.values()
                for scope in scopes
                if scope != "effective_nat"
            }
        )
    )
    sources = (
        ForwardingSource(
            **common,
            source_document_id=CONFIG_SOURCE_ID,
            source_name=CONFIG_NAME,
            content_sha256=sha256(b"synthetic configuration evidence\n").hexdigest(),
            purpose="configuration",
            command="show running-config all",
            complete_scopes=config_scopes,
        ),
        ForwardingSource(
            **common,
            source_document_id=NAT_SOURCE_ID,
            source_name="synthetic.nat",
            content_sha256=sha256(b"synthetic effective NAT evidence\n").hexdigest(),
            purpose="effective_nat",
            command="show nat",
            complete_scopes=("effective_nat",),
        ),
    )
    interfaces = tuple(
        ForwardingInterface(
            interface_id=name,
            label=name,
            physical_l3=True,
            security_level=level,
            security_status=DataStatus.KNOWN,
            location=forwarding_location(line),
        )
        for name, level, line in (("inside", 100, 1), ("outside", 0, 2))
    )
    acls = (
        ForwardingAcl(
            policy_id="INSIDE",
            configuration_id=CONFIGURATION_ID,
            status=DataStatus.KNOWN,
            complete=True,
            rules=(forwarding_rule(),),
            location=forwarding_location(3),
            reference="Explicit complete ACL",
        ),
        ForwardingAcl(
            policy_id="GLOBAL",
            configuration_id=CONFIGURATION_ID,
            status=DataStatus.KNOWN,
            complete=True,
            location=forwarding_location(4),
            reference="Explicit empty ACL",
        ),
    )
    bindings = (
        ForwardingBinding(
            policy_id="INSIDE",
            direction="in",
            interface_id="inside",
            location=forwarding_location(5),
        ),
        ForwardingBinding(policy_id="GLOBAL", direction="global", location=forwarding_location(6)),
    )
    toggles = tuple(
        ForwardingToggle(
            name=name, status=DataStatus.KNOWN, value=value, location=forwarding_location(line)
        )
        for name, value, line in (
            ("inter_interface", True, 7),
            ("intra_interface", False, 8),
            ("permit_vpn", True, 9),
        )
    )
    facts = {
        "interfaces": interfaces,
        "acl_definitions": acls,
        "acl_bindings": bindings,
        "same_security": toggles[:2],
        "vpn_bypass": toggles[2:],
    }
    inventories = tuple(
        FeatureInventory(
            feature=feature,
            status=DataStatus.KNOWN if feature in facts else DataStatus.ABSENT,
            item_count=len(facts.get(feature, ())),
            complete=True,
            enumeration_complete=True,
            source_document_ids=(
                NAT_SOURCE_ID if feature == "effective_nat" else CONFIG_SOURCE_ID,
            ),
            locations=tuple(item.location for item in facts.get(feature, ())),
            reference="Synthetic exhaustive feature inventory",
        )
        for feature in FEATURE_SCOPES
    )
    return empty_forwarding_context(
        **{
            "observed_at": OBSERVED_AT,
            "sources": sources,
            "inventories": inventories,
            "interfaces": interfaces,
            "acls": acls,
            "bindings": bindings,
            "toggles": toggles,
            "flow": forwarding_flow(
                new_connection=True,
                transit=True,
                non_vpn=True,
                non_fragment=True,
                tcp_syn=True,
                tcp_ack=False,
                tcp_payload_length=0,
            ),
            **changes,
        }
    )
