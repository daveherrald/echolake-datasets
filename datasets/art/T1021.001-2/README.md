# T1021.001-2: Remote Desktop Protocol

**MITRE ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001)
**Technique:** Remote Desktop Protocol
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.001 -TestNumbers 2` — Changing RDP Port to Non Standard Port via Powershell

## Telemetry (81 events)
- **Sysmon**: 30 events
- **Security**: 11 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
