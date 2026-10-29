# UserGate NGFW: read-only integration

Connection profiles: UGOS 6.1.5+ in major 6 over XML-RPC HTTP (TCP 4040);
UGOS 7 over HTTP (4040); UGOS 7.3.3+ over verified HTTPS (4443).
Real firmware interoperability remains unverified.

Desktop: Files and checks -> UserGate (read only). Select profile, host,
credentials, optionally a PEM CA for HTTPS, and a new JSON destination.
Collection runs in the background; the result is staged for normal analysis.
Passwords are not saved in snapshots/settings. HTTPS never falls back to HTTP.
Use HTTP only within a protected management network or VPN.

CLI (password requested interactively):

```powershell
python -m firewall_compliance usergate-collect ngfw.local ug6.json --family 6
python -m firewall_compliance usergate-collect ngfw.local ug7.json --family 7 --transport https --ca-file company-ca.pem
python -m firewall_compliance analyze ug7.json
```

Enable API access manually for account and zone. Prefer an account with read
permissions only. The application never configures API access or permissions.
The client permits only login/logout and an exact allowlist of reading methods:
firewall rules, NAT rules, zones, services, IP lists and their content. No arbitrary
RPC or mutation command is exposed. Login/logout manage an API session and may
produce audit events on the device.

Collection uses pagination, timeouts, response/item limits, protected XML parsing
and sanitized remote errors. Existing files are not overwritten. Collection
failure does not save a snapshot; a local write failure can leave a partial file.
Multiple API calls are not an atomic snapshot.

arxion-usergate-v1 JSON preserves raw rules and referenced objects. The importer
resolves static address lists, TCP/UDP/IP services and individual zones. Missing
references and unsupported selectors (users, applications, schedules, inversion,
service groups, dynamic lists) remain unknown/unsupported, never unrestricted.
NAT is retained without translation analysis. Configuration completeness is not
established. No database or existing persisted domain schema migration is needed.

Protocol references (vendor public examples are obsolete, not a compatibility guarantee):
- https://docs.usergate.com/nastrojka-servisa-xml-rpc_800.html
- https://docs.usergate.com/trebovaniya-k-setevomu-okruzheniyu_1068.html
- https://github.com/usergate/Migrations/blob/main/ug_ngfw_converter/src/utm.py
