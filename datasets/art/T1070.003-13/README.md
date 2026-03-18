# T1070.003-13: Clear Command History

**MITRE ATT&CK:** [T1070.003](https://attack.mitre.org/techniques/T1070/003)
**Technique:** Clear Command History
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.003 -TestNumbers 13` — Set Custom AddToHistoryHandler to Avoid History File Logging

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
