# T1021.001-4: Remote Desktop Protocol

**MITRE ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001)
**Technique:** Remote Desktop Protocol
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.001 -TestNumbers 4` — Disable NLA for RDP via Command Prompt

## Telemetry (83 events)
- **Sysmon**: 36 events
- **Security**: 12 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
