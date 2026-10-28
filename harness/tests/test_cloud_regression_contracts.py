"""Current Cloud Director discovery/authentication contracts, without live accounts."""

import json
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

from firewall_compliance.infrastructure.cloud_vmware import VMwareClient, VMwareConfig


def test_auto_version_discovery_precedes_tenant_auth_and_prefers_current_version():
    calls = []

    def transport(request: Request, timeout: int) -> bytes:
        calls.append(request)
        assert timeout == 30
        path = urlsplit(request.full_url).path
        if path == "/api/versions":
            assert request.get_method() == "GET"
            assert request.get_header("Authorization") is None
            assert request.get_header("Accept") == "application/*+xml"
            return (
                b'<SupportedVersions><VersionInfo deprecated="false">'
                b"<Version>39.0</Version></VersionInfo>"
                b'<VersionInfo deprecated="true"><Version>39.1</Version>'
                b"</VersionInfo></SupportedVersions>"
            )
        if path == "/oauth/tenant/Synthetic_tenant/token":
            assert request.get_method() == "POST"
            assert request.get_header("Authorization") is None
            assert parse_qs(request.data.decode()) == {
                "grant_type": ["refresh_token"],
                "refresh_token": ["synthetic-api-token"],
            }
            return b'{"access_token":"synthetic-access-token"}'
        assert path == "/api/org/" and request.get_method() == "GET"
        assert request.get_header("Authorization") == "Bearer synthetic-access-token"
        assert request.get_header("Accept") == "application/*+xml;version=39.0"
        return b'<OrgList><Org name="Synthetic_tenant"/></OrgList>'

    client = VMwareClient(
        VMwareConfig("https://vcd50-01.cloud.ru/tenant/Synthetic_tenant/", ""),
        "synthetic-api-token",
        transport=transport,
    )
    result = client.check_connection()
    assert result.state == "completed" and client.api_version == "39.0"
    assert [urlsplit(call.full_url).path for call in calls] == [
        "/api/versions",
        "/oauth/tenant/Synthetic_tenant/token",
        "/api/org/",
    ]
    assert "synthetic-api-token" not in json.dumps(result.requests)
    assert "synthetic-access-token" not in json.dumps(result.requests)


def test_explicit_unavailable_version_stops_before_sending_api_token():
    calls = []

    def transport(request: Request, _timeout: int) -> bytes:
        calls.append(request)
        assert urlsplit(request.full_url).path == "/api/versions"
        assert request.get_method() == "GET" and request.data is None
        assert request.get_header("Authorization") is None
        return (
            b'<SupportedVersions><VersionInfo deprecated="false">'
            b"<Version>39.1</Version></VersionInfo></SupportedVersions>"
        )

    result = VMwareClient(
        VMwareConfig("https://vcd50-01.cloud.ru", "Synthetic_tenant", "36.1"),
        "synthetic-api-token",
        transport=transport,
    ).check_connection()
    assert result.state == "failed" and len(calls) == 1
    assert "36.1" in result.errors[0]["message"] and "39.1" in result.errors[0]["message"]
    assert "synthetic-api-token" not in json.dumps(result.errors)
