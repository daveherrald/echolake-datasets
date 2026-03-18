# T1070.001-2: Clear Windows Event Logs

**MITRE ATT&CK:** [T1070.001](https://attack.mitre.org/techniques/T1070/001)
**Technique:** Clear Windows Event Logs
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.001 -TestNumbers 2` — Delete System Logs Using Clear-EventLog

## Telemetry (214 events)
- **Sysmon**: 36 events
- **Security**: 127 events
- **Powershell**: 49 events
- **System**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
