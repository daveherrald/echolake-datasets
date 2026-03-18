# T1047-10: Windows Management Instrumentation

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047)
**Technique:** Windows Management Instrumentation
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1047 -TestNumbers 10` — Application uninstall using WMIC

## Telemetry (103 events)
- **Sysmon**: 26 events
- **Security**: 30 events
- **Powershell**: 34 events
- **Application**: 13 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
