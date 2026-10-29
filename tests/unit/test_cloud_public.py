"""Synthetic provider contracts and an independent official SDK signing vector."""

from __future__ import annotations

import json
from dataclasses import asdict
from threading import Event
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request
from uuid import UUID

import pytest

from firewall_compliance.devices.cloud.cloud_ru.public_client import (
    AdvancedClient,
    AdvancedConfig,
    CloudCredentials,
    EvolutionClient,
    EvolutionConfig,
    PublicSelection,
    sign_advanced,
)
from firewall_compliance.devices.cloud.cloud_ru.vmware.client import CloudError

PROJECT = "01234567-89ab-cdef-0123-456789abcdef"
ADV_PROJECT = PROJECT.replace("-", "")
ITEM_ID = "11111111-2222-3333-4444-555555555555"
KEYS = CloudCredentials("SYNTHETICAK", "SYNTHETICSK")


def _bytes(payload: object) -> bytes:
    return json.dumps(payload).encode()


def test_signing_matches_official_cloud_ru_sdk_vector() -> None:
    # Generated using SDK 2.0.4 linked by the official Python Signing Guide:
    # https://support.hc.cloud.ru/en-us/devg/apisign/api-sign-sdk-python.html
    request = Request(
        "https://vpc.ru-moscow-1.hc.sbercloud.ru/v1/"
        + ADV_PROJECT
        + "/vpcs?limit=100&marker="
        + ITEM_ID,
        headers={"X-Project-Id": ADV_PROJECT},
    )
    sign_advanced(request, KEYS, "20261013T120000Z")
    assert request.get_header("Authorization") == (
        "SDK-HMAC-SHA256 Access=SYNTHETICAK, SignedHeaders=host;x-project-id;x-sdk-date, "
        "Signature=6c8d202b17e88363ffa6d489e45c9baea549050acad064308b08487c286622dc"
    )
    assert request.get_header("X-sdk-date") == "20261013T120000Z"
    assert KEYS.secret_key not in repr(KEYS)


def test_evolution_collects_resources_rules_and_networks_without_secrets() -> None:
    calls: list[Request] = []

    def transport(request: Request, _timeout: int) -> bytes:
        calls.append(request)
        parsed = urlsplit(request.full_url)
        if parsed.path.endswith("/auth/token"):
            assert request.get_method() == "POST"
            assert json.loads(request.data) == {"keyId": KEYS.access_key, "secret": KEYS.secret_key}
            return _bytes({"access_token": "synthetic-bearer"})
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer synthetic-bearer"
        if parsed.path.endswith("/rules"):
            assert "project_id" not in parse_qs(parsed.query)
            return _bytes({"items": [{"id": ITEM_ID, "direction": "ingress"}], "total": 1})
        assert parse_qs(parsed.query)["project_id"] == [PROJECT]
        return _bytes(
            {
                "items": [
                    {
                        "id": ITEM_ID,
                        "name": parsed.path,
                        "vnc_url": "private-console",
                        "metadata_fields": [{"password": "private-password"}],
                    }
                ],
                "total": 1,
            }
        )

    result = EvolutionClient(EvolutionConfig(PROJECT), KEYS, transport=transport).scan(
        PublicSelection(
            ("vms", "subnets", "security_groups", "interfaces"), ("vm_networks", "security_rules")
        )
    )
    assert result.state == "completed"
    assert len(result.records) == 4
    assert result.records[0]["data"]["vm_networks"]
    assert result.records[2]["data"]["security_rules"][0]["direction"] == "ingress"
    serialized = json.dumps(asdict(result))
    for secret in (
        KEYS.access_key,
        KEYS.secret_key,
        "synthetic-bearer",
        "private-password",
        "private-console",
    ):
        assert secret not in serialized
    assert len(calls) == 7


def test_evolution_offset_pagination_uses_actual_count() -> None:
    offsets: list[int] = []

    def transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return _bytes({"access_token": "access"})
        offset = int(parse_qs(urlsplit(request.full_url).query)["offset"][0])
        offsets.append(offset)
        return _bytes({"items": [{"id": str(UUID(int=offset + 1))}], "total": 3})

    result = EvolutionClient(EvolutionConfig(PROJECT), KEYS, transport=transport).scan(
        PublicSelection(("subnets",))
    )
    assert result.state == "completed"
    assert offsets == [0, 1, 2]
    assert len(result.records) == 3


def test_advanced_collector_signs_gets_and_uses_project_scope() -> None:
    calls: list[Request] = []

    def transport(request: Request, _timeout: int) -> bytes:
        calls.append(request)
        assert request.get_method() == "GET"
        assert request.get_header("X-project-id") == ADV_PROJECT
        assert "SDK-HMAC-SHA256" in request.get_header("Authorization")
        assert KEYS.secret_key not in request.get_header("Authorization")
        parsed = urlsplit(request.full_url)
        if parsed.path.endswith("/os-interface"):
            return _bytes({"interfaceAttachments": [{"port_id": ITEM_ID, "fixed_ips": []}]})
        if parsed.path.endswith("/security-groups/" + ITEM_ID):
            return _bytes({"security_group": {"security_group_rules": [{"direction": "ingress"}]}})
        key = {
            "detail": "servers",
            "vpcs": "vpcs",
            "subnets": "subnets",
            "security-groups": "security_groups",
        }[parsed.path.rsplit("/", 1)[-1]]
        items = [] if "marker" in parse_qs(parsed.query) else [{"id": ITEM_ID, "name": key}]
        return _bytes({key: items})

    result = AdvancedClient(AdvancedConfig(ADV_PROJECT), KEYS, transport=transport).scan(
        PublicSelection(
            ("vms", "vpcs", "subnets", "security_groups"), ("vm_networks", "security_rules")
        )
    )
    assert result.state == "completed"
    assert len(result.records) == 4
    assert result.records[0]["data"]["vm_networks"]
    assert result.records[3]["data"]["security_rules"]
    assert len(calls) == 10
    assert KEYS.access_key not in json.dumps(asdict(result))


def test_advanced_marker_pagination_does_not_assume_requested_page_size() -> None:
    markers = []

    def transport(request: Request, _timeout: int) -> bytes:
        marker = parse_qs(urlsplit(request.full_url).query).get("marker", [""])[0]
        markers.append(marker)
        return _bytes({"vpcs": [] if marker == ITEM_ID else [{"id": ITEM_ID}]})

    result = AdvancedClient(AdvancedConfig(ADV_PROJECT), KEYS, transport=transport).scan(
        PublicSelection(("vpcs",))
    )
    assert result.state == "completed"
    assert markers == ["", ITEM_ID]


@pytest.mark.parametrize("platform", ["advanced", "evolution"])
def test_duplicate_or_invalid_response_never_becomes_success(platform: str) -> None:
    def transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return _bytes({"access_token": "access"})
        if platform == "advanced":
            return _bytes({"subnets": [{"id": ITEM_ID}]})
        return _bytes({"items": [{"id": ITEM_ID}], "total": 2})

    client = (
        AdvancedClient(AdvancedConfig(ADV_PROJECT), KEYS, transport=transport)
        if platform == "advanced"
        else EvolutionClient(EvolutionConfig(PROJECT), KEYS, transport=transport)
    )
    result = client.scan(PublicSelection(("subnets",)))
    assert result.state == "failed"
    assert result.errors


def test_permission_error_keeps_other_resources_and_marks_partial() -> None:
    def transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return _bytes({"access_token": "access"})
        if "/security-groups" in request.full_url:
            raise CloudError("HTTP 403: Недостаточно прав.")
        return _bytes({"items": [{"id": ITEM_ID}], "total": 1})

    result = EvolutionClient(EvolutionConfig(PROJECT), KEYS, transport=transport).scan(
        PublicSelection(("subnets", "security_groups"))
    )
    assert result.state == "partial"
    assert len(result.records) == 1
    assert "403" in result.errors[0]["message"]


@pytest.mark.parametrize("platform", ["advanced", "evolution"])
def test_cancel_before_scan_does_not_transmit_credentials(platform: str) -> None:
    cancel = Event()
    cancel.set()

    def transport(*_: object) -> bytes:
        raise AssertionError("Network must not be called")

    client = (
        AdvancedClient(AdvancedConfig(ADV_PROJECT), KEYS, cancel=cancel, transport=transport)
        if platform == "advanced"
        else EvolutionClient(EvolutionConfig(PROJECT), KEYS, cancel=cancel, transport=transport)
    )
    result = client.scan(PublicSelection(("vms",)))
    assert result.state == "cancelled"
    assert not result.requests


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://evil.test",
        "http://vpc.ru-moscow-1.hc.sbercloud.ru",
        "https://vpc.ru-moscow-1.hc.sbercloud.ru.evil.test",
        "https://vpc.ru-moscow-1.hc.sbercloud.ru/path",
        "https://vpc.ru-moscow-1.hc.sbercloud.ru@evil.test",
    ],
)
def test_advanced_rejects_credential_exfiltration_endpoint(endpoint: str) -> None:
    with pytest.raises(ValueError):
        AdvancedConfig(ADV_PROJECT, vpc_endpoint=endpoint)


@pytest.mark.parametrize(
    "constructor,project", [(AdvancedConfig, "invalid"), (EvolutionConfig, "invalid")]
)
def test_project_id_must_match_platform_format(constructor: object, project: str) -> None:
    with pytest.raises(ValueError):
        constructor(project)


def test_evolution_probe_checks_project_identity() -> None:
    client = EvolutionClient(
        EvolutionConfig(PROJECT),
        KEYS,
        transport=lambda req, _: _bytes(
            {"access_token": "access"} if req.get_method() == "POST" else {"id": PROJECT}
        ),
    )
    assert client.check_connection().state == "completed"
