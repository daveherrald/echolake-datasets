# T1021.006-2: Windows Remote Management

**MITRE ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006)
**Technique:** Windows Remote Management
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.006 -TestNumbers 2` — Remote Code Execution with PS Credentials Using Invoke-Command

## Telemetry (995 events)
- **Sysmon**: 77 events
- **Security**: 59 events
- **Powershell**: 850 events
- **System**: 8 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
