# Ideco NGFW v23: read-only API integration

Initial support: classic NGFW v23 (STANDARD/FSTEK/NGFW-FSTEK), verified HTTPS.
VPP/BPF and Ideco Center endpoints are rejected. Actual device interoperability
is not yet verified. The supplied endpoint must expose the required classic
context; automatic VCE discovery/switching is not implemented.

Desktop: Files and checks -> Ideco (read only). Enter host, credentials and
optional PEM CA path. Background collection saves a new JSON file and stages it
for ordinary analysis. API passwords and session cookies are not saved.

CLI (password prompted without echo):

```powershell
python -m firewall_compliance ideco-collect ngfw.local ideco.json --username admin
python -m firewall_compliance ideco-collect ngfw.local ideco.json --ca-file company-ca.pem --port 8443
python -m firewall_compliance analyze ideco.json
```

Collection permits only session login/logout plus exact GET paths for version,
FORWARD/INPUT/DNAT/SNAT, aliases, zones, firewall state/settings/status. No device
configuration changes, insecure TLS mode, redirects or protocol downgrade.
Use an account with sufficient reading permissions; the application never
changes permissions. Login/logout can create device audit events.

The additive arxion-ideco-v1 JSON format requires no SQLite/domain migration.
Unknown selectors and missing object references remain explicitly unsupported,
never unrestricted. Parser handles static addresses, ranges, nested static lists,
TCP/UDP/IP services and zones conservatively. Multiple AND address groups,
inversion, constrained source ports, schedules, user selectors and security
profiles limit analysis. NAT remains in the snapshot without translation analysis.
No completeness, atomic snapshot, verified rule order or effective forwarding
claim is made. Center and system rules may be missing. Interface/routing,
counters and traffic journal collection are deferred.

Responses and total collection size are bounded; errors omit remote bodies.
Existing files are not overwritten. A local write failure may leave a partial file.

References:
- https://docs.ideco.ru/api/v23/ru/ngfw/
- https://docs.ideco.ru/api/v23/ru/ngfw/admin-login-api
- https://docs.ideco.ru/api/v23/ru/ngfw/access-rules-api/firewall
- https://docs.ideco.ru/api/v23/ru/ngfw/objects-api
