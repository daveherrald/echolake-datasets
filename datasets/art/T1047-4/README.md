# T1047-4: Windows Management Instrumentation

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047)
**Technique:** Windows Management Instrumentation
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1047 -TestNumbers 4` — WMI Reconnaissance List Remote Services

## Telemetry (79 events)
- **Sysmon**: 31 events
- **Security**: 13 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
