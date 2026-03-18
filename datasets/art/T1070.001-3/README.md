# T1070.001-3: Clear Windows Event Logs

**MITRE ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001)
**Technique:** Clear Windows Event Logs
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.001 -TestNumbers 3` — Clear Event Logs via VBA

## Telemetry (139 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 92 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
