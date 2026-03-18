# T1047-8: Windows Management Instrumentation

**MITRE ATT&CK:** [T1047](https://attack.mitre.org/techniques/T1047)
**Technique:** Windows Management Instrumentation
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1047 -TestNumbers 8` — Create a Process using obfuscated Win32_Process

## Telemetry (100 events)
- **Sysmon**: 49 events
- **Security**: 11 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
