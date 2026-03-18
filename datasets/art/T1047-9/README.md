# T1047-9: Windows Management Instrumentation

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047)
**Technique:** Windows Management Instrumentation
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1047 -TestNumbers 9` — WMI Execute rundll32

## Telemetry (75 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
