# T1012-4: Query Registry

**MITRE ATT&CK:** [T1012](https://attack.mitre.org/techniques/T1012)
**Technique:** Query Registry
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1012 -TestNumbers 4` — Reg query for AlwaysInstallElevated status

## Telemetry (68 events)
- **Sysmon**: 18 events
- **Security**: 16 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
