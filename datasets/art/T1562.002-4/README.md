# T1562.002-4: Disable Windows Event Logging

**MITRE ATT&CK:** [T1562.002](https://attack.mitre.org/techniques/T1562/002)
**Technique:** Disable Windows Event Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.002 -TestNumbers 4` — Impair Windows Audit Log Policy

## Telemetry (94 events)
- **Sysmon**: 20 events
- **Security**: 36 events
- **Powershell**: 35 events
- **Application**: 2 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
