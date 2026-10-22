"""Human projections preserve unknowns, full details and management distinctions."""

import copy
from datetime import UTC, datetime

import pytest

from firewall_compliance.domain import ParseResult
from firewall_compliance.interfaces.desktop.object_presentation import (
    endpoint_summary,
    object_details,
    object_summary,
    rule_details,
    rule_endpoint_summary,
    rule_scope_label,
    rule_service_summary,
    service_summary,
)
from firewall_compliance.parsers.comware import ComwareParser
from firewall_compliance.parsers.contracts import ParseRequest, SourceDocument


def test_known_any_and_unknown_references_are_not_equivalent() -> None:
    known = {"kind": "any", "name": "any", "resolution_status": "known"}
    assert endpoint_summary([known]) == "Любой адрес"
    assert endpoint_summary([{**known, "resolution_status": "unknown"}]) == "any · Не определено"
    assert endpoint_summary([{"kind": "object", "name": "office"}]) == "office · Не определено"
    assert endpoint_summary([]) == "Не указано"


def test_short_preview_and_complete_values_including_ipv6_ranges_fqdn() -> None:
    value = {
        "endpoint_id": "e1",
        "name": "office",
        "kind": "group",
        "resolution_status": "known",
        "cidrs": ["10.0.0.0/24", "2001:db8::/32", "10.1.0.0/24", "10.2.0.0/24"],
        "ip_ranges": [{"start": "10.3.0.1", "end": "10.3.0.8"}],
        "fqdn": "example.invalid",
    }
    before = copy.deepcopy(value)
    preview = object_summary(value)
    assert "ещё 3" in preview
    assert "10.2.0.0/24" not in preview
    fields = dict(object_details(value))
    assert "10.2.0.0/24" in fields["CIDR"]
    assert "2001:db8::/32" in fields["Значение"]
    assert fields["Диапазоны адресов"] == "10.3.0.1–10.3.0.8"
    assert fields["FQDN"] == "example.invalid"
    assert value == before


def test_services_do_not_duplicate_protocol_or_guess_snmp_port() -> None:
    assert (
        service_summary([{"protocol": "ip", "name": "ip", "resolution_status": "known"}])
        == "Любой IP-протокол"
    )
    known_tcp = {
        "service_id": "s",
        "protocol": "tcp",
        "resolution_status": "known",
        "port_ranges": [{"start": 443, "end": 443}, {"start": 8000, "end": 8100}],
    }
    assert service_summary([known_tcp]) == "TCP · 443, 8000–8100"
    assert service_summary([{**known_tcp, "port_ranges": []}]) == "TCP · все порты"
    unknown = {
        "service_id": "snmp",
        "name": "SNMP management scope",
        "protocol": "other",
        "resolution_status": "unknown",
    }
    assert "161" not in object_summary(unknown)
    assert "порт не извлечён" in object_summary(unknown)
    assert "Не определено" in object_summary(unknown)
    assert dict(object_details(unknown))["Диапазоны портов"] == "Не указаны"


def test_rule_inspector_keeps_statuses_scope_and_all_known_semantics() -> None:
    rule = {
        "rule_id": "r1",
        "name": "SNMP ACL",
        "configuration_id": "c1",
        "sequence": 3,
        "enabled": False,
        "action": "drop",
        "policy_id": "management:snmp:acl:2000",
        "policy_direction": "in",
        "policy_semantics": "first_match",
        "sources": [{"kind": "any", "name": "any", "resolution_status": "known"}],
        "source_status": "known",
        "destinations": [],
        "destination_status": "unknown",
        "services": [],
        "service_status": "unsupported",
        "logging_enabled": None,
        "logging_status": "unknown",
        "description_status": "absent",
        "owner": "team",
        "source_location": {
            "source_name": "a.cfg",
            "line_start": 8,
            "line_end": 9,
            "object_id": "oid",
        },
    }
    rows = dict(rule_details(rule))
    assert rows["Состояние"] == "Отключено"
    assert rows["Действие"] == "Отбросить (drop)"
    assert rows["Область"] == "Управление устройством"
    assert rows["Порядок применения"] == "Первое совпадение"
    assert "Не определено" in rows["Куда"]
    assert "Не поддержано" in rows["Сервис"]
    assert rows["Владелец"] == "team"
    assert "oid" in rows["Расположение"]
    assert rule_scope_label({"policy_id": "acl:2000"}) == "Область применения не подтверждена"


@pytest.mark.parametrize(
    "status_field", ["source_status", "destination_status", "service_status", "match_status"]
)
def test_unconfirmed_rule_predicates_do_not_inherit_unrestricted_leaf_semantics(
    status_field: str,
) -> None:
    rule = {
        "sources": [{"kind": "any", "name": "any", "resolution_status": "known"}],
        "destinations": [{"kind": "any", "name": "any", "resolution_status": "known"}],
        "services": [{"protocol": "tcp", "name": "tcp", "resolution_status": "known"}],
        "source_status": "known",
        "destination_status": "known",
        "service_status": "known",
        "match_status": "known",
    }
    rule[status_field] = "unsupported"
    before = copy.deepcopy(rule)
    if status_field in {"source_status", "match_status"}:
        assert "Любой адрес" not in rule_endpoint_summary(rule, "sources")
        assert "Не поддержано" in rule_endpoint_summary(rule, "sources")
    if status_field in {"destination_status", "match_status"}:
        assert "Любой адрес" not in rule_endpoint_summary(rule, "destinations")
    if status_field in {"service_status", "match_status"}:
        assert "все порты" not in rule_service_summary(rule)
        assert "порт не извлечён" in rule_service_summary(rule)
    assert rule == before


def test_real_comware_unsupported_source_port_is_not_displayed_as_unrestricted_rule() -> None:
    now = datetime(2026, 10, 15, tzinfo=UTC)
    parsed = ComwareParser().parse(
        ParseRequest(
            source=SourceDocument(
                source_name="synthetic.cfg",
                captured_at=now,
                content=(
                    b"version 7.1.045\nsysname LAB\nacl advanced 3000\n"
                    b" rule 5 permit tcp source-port eq 1234 destination 192.0.2.1 0 "
                    b"destination-port eq 443\n#\n"
                ),
            ),
            imported_at=now,
        )
    )
    assert isinstance(parsed, ParseResult)
    rule = parsed.rules[0].model_dump(mode="json")
    before = copy.deepcopy(rule)
    assert rule["match_status"] == "unsupported"
    rows = dict(rule_details(rule))
    for field, title in (("sources", "Откуда"), ("destinations", "Куда")):
        assert "Любой адрес" not in rule_endpoint_summary(rule, field)
        assert "полное условие не подтверждено" in rows[title]
    assert "все порты" not in rule_service_summary(rule)
    assert "Не поддержано" in rows["Сервис"]
    assert rule == before


def test_partial_rule_retains_explicit_extracted_cidr_and_port_under_qualifier() -> None:
    rule = {
        "sources": [{"kind": "subnet", "cidrs": ["192.0.2.0/24"], "resolution_status": "known"}],
        "services": [
            {
                "protocol": "tcp",
                "port_ranges": [{"start": 443, "end": 443}],
                "resolution_status": "known",
            }
        ],
        "source_status": "known",
        "service_status": "known",
        "match_status": "unsupported",
    }
    assert "192.0.2.0/24" in rule_endpoint_summary(rule, "sources")
    assert "TCP · 443" in rule_service_summary(rule)
    assert "полное условие не подтверждено" in rule_service_summary(rule)
