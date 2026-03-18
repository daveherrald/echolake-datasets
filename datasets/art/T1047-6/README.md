# T1047-6: Windows Management Instrumentation

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047)
**Technique:** Windows Management Instrumentation
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1047 -TestNumbers 6` — WMI Execute Remote Process

## Telemetry (77 events)
- **Sysmon**: 29 events
- **Security**: 13 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
