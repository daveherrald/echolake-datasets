# T1135-11: Network Share Discovery

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135)
**Technique:** Network Share Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1135 -TestNumbers 11` — Enumerate All Network Shares with SharpShares

## Telemetry (91 events)
- **Sysmon**: 42 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
