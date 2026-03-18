# T1529-12: System Shutdown/Reboot

**MITRE ATT&CK:** [T1529](https://attack.mitre.org/techniques/T1529)
**Technique:** System Shutdown/Reboot
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1529 -TestNumbers 12` — Logoff System - Windows

## Telemetry (144 events)
- **Sysmon**: 75 events
- **Security**: 32 events
- **Powershell**: 34 events
- **Application**: 2 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
