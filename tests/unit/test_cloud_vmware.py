"""Cloud Director contracts using synthetic API responses only."""

from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from threading import Event
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

import pytest
from hypothesis import given
from hypothesis import strategies as st

from firewall_compliance.devices.cloud.cloud_ru.vmware.client import (
    CloudError,
    ScanSelection,
    Transport,
    VMwareClient,
    VMwareConfig,
    _json,
    _xml,
)
from firewall_compliance.infrastructure.windows_secrets import protect_secret, unprotect_secret
from firewall_compliance.interfaces.desktop.project_store import ProjectStore

SITE = "https://vcd01-01.cloud.ru"
CONFIG = VMwareConfig(SITE, "test-tenant")
GATEWAY_ID = "urn:vcloud:gateway:11111111-2222-3333-4444-555555555555"
VM_HREF = SITE + "/api/vApp/vm-11111111-2222-3333-4444-555555555555"


def _bytes(payload: object) -> bytes:
    return json.dumps(payload).encode()


def _with_versions(transport: Transport, *versions: str) -> Transport:
    """Answer the unauthenticated discovery request before the scenario's API calls."""
    advertised = versions or ("39.1",)

    def versioned(request: Request, timeout: int) -> bytes:
        if urlsplit(request.full_url).path == "/api/versions":
            assert request.get_method() == "GET"
            assert request.get_header("Authorization") is None
            assert request.get_header("Accept") == "application/*+xml"
            return (
                "<SupportedVersions>"
                + "".join(
                    f'<VersionInfo deprecated="false"><Version>{version}</Version></VersionInfo>'
                    for version in advertised
                )
                + "</SupportedVersions>"
            ).encode()
        return transport(request, timeout)

    return versioned


def test_authentication_and_all_selected_resources_are_collected() -> None:
    calls: list[Request] = []

    def transport(request: Request, timeout: int) -> bytes:
        calls.append(request)
        parsed = urlsplit(request.full_url)
        assert timeout == 30
        if parsed.path.endswith("/token"):
            assert request.get_method() == "POST"
            assert parse_qs(request.data.decode())["refresh_token"] == ["synthetic-api-token"]
            assert request.get_header("Authorization") is None
            return _bytes({"access_token": "synthetic-access-token"})
        assert request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer synthetic-access-token"
        if parsed.path == "/api/query":
            assert parse_qs(parsed.query)["type"] == ["vm"]
            return (
                f'<QueryResultRecords total="1"><VMRecord name="vm-1" href="{VM_HREF}"/>'
                "</QueryResultRecords>"
            ).encode()
        if parsed.path.endswith("networkConnectionSection"):
            return (
                b'<NetworkConnectionSection><NetworkConnection network="net-1">'
                b"<IpAddress>192.0.2.1</IpAddress></NetworkConnection></NetworkConnectionSection>"
            )
        if parsed.path.endswith("edgeGateways"):
            return _bytes({"resultTotal": 1, "values": [{"id": GATEWAY_ID, "name": "edge-1"}]})
        if parsed.path.endswith("firewall/rules"):
            return _bytes(
                {"userDefinedRules": [{"id": "1", "actionValue": "ALLOW"}], "systemRules": []}
            )
        if parsed.path.endswith("nat/rules"):
            return _bytes({"values": [{"id": "nat-1"}], "resultTotal": 1})
        if parsed.path.endswith("routing/staticRoutes"):
            return _bytes({"values": [{"networkCidr": "192.0.2.0/24"}]})
        if parsed.path.endswith("orgVdcNetworks"):
            return _bytes({"values": [{"id": "net-1", "name": "network"}], "pageCount": 1})
        raise AssertionError(parsed.path)

    client = VMwareClient(CONFIG, "synthetic-api-token", transport=_with_versions(transport))
    result = client.scan(
        ScanSelection(("vms", "edges", "networks"), ("vm_networks", "firewall", "nat", "routes"))
    )
    assert result.state == "completed"
    assert len(result.records) == 3
    assert result.records[0]["data"]["vm_networks"][0]["IpAddress"] == "192.0.2.1"
    assert result.records[1]["data"]["firewall"]["userDefinedRules"][0]["id"] == "1"
    assert len(calls) == 8
    assert len(result.requests) == 9
    assert result.requests[0] == {"method": "GET", "path": "/api/versions", "status": "ok"}
    assert urlsplit(calls[0].full_url).path == "/oauth/tenant/test-tenant/token"
    assert client.api_version == "39.1"
    assert "synthetic-api-token" not in json.dumps(asdict(result))
    assert "synthetic-access-token" not in json.dumps(asdict(result))


def test_pagination_collects_all_pages() -> None:
    pages: list[int] = []

    def transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return _bytes({"access_token": "access"})
        page = int(parse_qs(urlsplit(request.full_url).query)["page"][0])
        pages.append(page)
        return _bytes({"resultTotal": 2, "pageCount": 2, "values": [{"id": str(page)}]})

    result = VMwareClient(CONFIG, "api", transport=_with_versions(transport)).scan(
        ScanSelection(("networks",))
    )
    assert result.state == "completed"
    assert pages == [1, 2]
    assert len(result.records) == 2


def test_denied_resource_is_partial_and_not_reported_as_empty_success() -> None:
    def transport(request: Request, _timeout: int) -> bytes:
        if request.get_method() == "POST":
            return _bytes({"access_token": "access"})
        if "/firewall/" in request.full_url:
            raise CloudError("HTTP 403: Недостаточно прав на чтение ресурса.")
        return _bytes({"values": [{"id": GATEWAY_ID, "name": "edge"}], "resultTotal": 1})

    result = VMwareClient(CONFIG, "api", transport=_with_versions(transport)).scan(
        ScanSelection(("edges",), ("firewall",))
    )
    assert result.state == "partial"
    assert "403" in result.errors[0]["message"]
    assert "firewall" not in result.records[0]["data"]


def test_missing_collection_shape_fails_instead_of_empty_success() -> None:
    result = VMwareClient(
        CONFIG,
        "api",
        transport=_with_versions(
            lambda req, _: _bytes(
                {"access_token": "access"} if req.get_method() == "POST" else {"unexpected": []}
            )
        ),
    ).scan(ScanSelection(("networks",)))
    assert result.state == "failed"
    assert result.errors
    assert "values" in result.errors[0]["message"]


def test_incomplete_pagination_is_an_error() -> None:
    result = VMwareClient(
        CONFIG,
        "api",
        transport=_with_versions(
            lambda req, _: _bytes(
                {"access_token": "access"}
                if req.get_method() == "POST"
                else {"resultTotal": 2, "values": []}
            )
        ),
    ).scan(ScanSelection(("networks",)))
    assert result.state == "failed"
    assert "Пагинация" in result.errors[0]["message"]


def test_inconsistent_page_count_does_not_hide_missing_records() -> None:
    result = VMwareClient(
        CONFIG,
        "api",
        transport=_with_versions(
            lambda req, _: _bytes(
                {"access_token": "access"}
                if req.get_method() == "POST"
                else {"resultTotal": 2, "pageCount": 1, "values": [{"id": "1"}]}
            )
        ),
    ).scan(ScanSelection(("networks",)))
    assert result.state == "failed"
    assert result.errors
    assert "Последняя страница" in result.errors[0]["message"]


@pytest.mark.parametrize("version,path_version", [("36.1", "1.0.0"), ("38.1", "2.0.0")])
def test_firewall_endpoint_version_follows_config(version: str, path_version: str) -> None:
    paths: list[str] = []

    def transport(request: Request, _timeout: int) -> bytes:
        path = urlsplit(request.full_url).path
        paths.append(path)
        if path.endswith("/token"):
            return _bytes({"access_token": "access"})
        if path.endswith("/edgeGateways"):
            return _bytes({"values": [{"id": GATEWAY_ID}], "resultTotal": 1})
        return _bytes({"userDefinedRules": []})

    result = VMwareClient(
        VMwareConfig(SITE, "tenant", version), "api", transport=_with_versions(transport, version)
    ).scan(ScanSelection(("edges",), ("firewall",)))
    assert result.state == "completed"
    assert paths[-1] == f"/cloudapi/{path_version}/edgeGateways/{GATEWAY_ID}/firewall/rules"


def test_cancel_before_authentication_does_not_make_requests() -> None:
    cancel = Event()
    cancel.set()

    def transport(_req: Request, _timeout: int) -> bytes:
        raise AssertionError("No network request allowed")

    result = VMwareClient(CONFIG, "api", cancel=cancel, transport=transport).scan(
        ScanSelection(("vms",))
    )
    assert result.state == "cancelled"
    assert not result.requests


def test_connection_verifies_tenant_access() -> None:
    for tenant, expected in (("test-tenant", "completed"), ("other", "failed")):
        result = VMwareClient(
            CONFIG,
            "api",
            transport=_with_versions(
                lambda req, _, tenant=tenant: (
                    _bytes({"access_token": "access"})
                    if req.get_method() == "POST"
                    else f'<OrgList><Org name="{tenant}"/></OrgList>'.encode()
                )
            ),
        ).check_connection()
        assert result.state == expected


@pytest.mark.parametrize(
    "site",
    [
        "http://vcd01-01.cloud.ru",
        "https://cloud.ru.evil.test",
        "https://vcd01-01.cloud.ru@evil.test",
        "https://evil.test",
        "https://vcd01-01.cloud.ru/path",
        "https://vcd01-01.cloud.ru?secret=x",
        "https://vcd01-01.cloud.ru:8443",
    ],
)
def test_config_rejects_unsafe_endpoint(site: str) -> None:
    with pytest.raises(ValueError):
        VMwareConfig(site, "tenant")


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=30))
def test_endpoint_hostname_confusion_is_rejected(suffix: str) -> None:
    with pytest.raises(ValueError):
        VMwareConfig(f"https://vcd01-01.cloud.ru.{suffix}", "tenant")


def test_remote_vm_reference_cannot_receive_bearer_token() -> None:
    client = VMwareClient(CONFIG, "api", transport=lambda *_: b"")
    with pytest.raises(CloudError):
        client._vm_connections({"href": "https://evil.test/api/vApp/vm-abcd"})
    assert not client.requests


@pytest.mark.parametrize(
    "data", [b'<root><!ENTITY x "value"></root>', b"<!DOCTYPE root><root/>", b"invalid"]
)
def test_invalid_xml_is_rejected(data: bytes) -> None:
    with pytest.raises(CloudError):
        _xml(data)


@pytest.mark.parametrize("data", [b"[]", b"null", b"invalid"])
def test_invalid_json_is_rejected(data: bytes) -> None:
    with pytest.raises(CloudError):
        _json(data)


@pytest.mark.parametrize(
    "resources,data",
    [((), ()), (("vms",), ("firewall",)), (("edges",), ("vm_networks",)), (("invalid",), ())],
)
def test_selection_rejects_incompatible_data(
    resources: tuple[str, ...], data: tuple[str, ...]
) -> None:
    with pytest.raises(ValueError):
        ScanSelection(resources, data)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI")
def test_dpapi_and_project_scans_keep_credentials_out_of_results(tmp_path: Path) -> None:
    token = "synthetic-secret-for-dpapi-only"
    protected = protect_secret(token)
    assert token not in protected
    assert unprotect_secret(protected) == token
    store = ProjectStore(tmp_path / "projects.sqlite3")
    first = store.create_project("First")
    second = store.create_project("Second")
    store.save_vmware_integration(first, asdict(CONFIG), token)
    assert store.get_vmware_token(first) == token
    assert store.get_vmware_integration(second) is None
    assert "token" not in store.get_project(first)["settings"]
    scan_id = store.create_cloud_scan(first, {"resources": ["vms"]}, asdict(CONFIG))
    store.finish_cloud_scan(scan_id, {"state": "completed", "records": [], "errors": []})
    assert len(store.list_cloud_scans(first)) == 1
    assert not store.list_cloud_scans(second)
    assert token not in json.dumps(store.list_cloud_scans(first))
    with sqlite3.connect(store.path) as db:
        assert db.execute("SELECT protected_secret FROM integrations").fetchone()[0] != token
    assert token.encode() not in store.path.read_bytes()
    store.delete_vmware_integration(first)
    with pytest.raises(ValueError):
        store.get_vmware_token(first)
