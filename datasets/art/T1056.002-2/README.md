# T1056.002-2: GUI Input Capture

**MITRE ATT&CK:** [T1056.002](https://attack.mitre.org/techniques/T1056/002)
**Technique:** GUI Input Capture
**Tactic(s):** collection, credential-access
**ART Test:** `Invoke-AtomicTest T1056.002 -TestNumbers 2` — PowerShell - Prompt User for Password

## Telemetry (96 events)
- **Sysmon**: 43 events
- **Security**: 14 events
- **Powershell**: 33 events
- **Taskscheduler**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
