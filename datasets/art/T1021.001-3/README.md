# T1021.001-3: Remote Desktop Protocol

**MITRE ATT&CK:** [T1021.001](https://attack.mitre.org/techniques/T1021/001)
**Technique:** Remote Desktop Protocol
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.001 -TestNumbers 3` — Changing RDP Port to Non Standard Port via Command_Prompt

## Telemetry (92 events)
- **Sysmon**: 39 events
- **Security**: 19 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
