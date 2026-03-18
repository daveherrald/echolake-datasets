# T1529-2: System Shutdown/Reboot

**MITRE ATT&CK:** [T1529](https://attack.mitre.org/techniques/T1529)
**Technique:** System Shutdown/Reboot
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1529 -TestNumbers 2` — Restart System - Windows

## Telemetry (1802 events)
- **Sysmon**: 1203 events
- **Security**: 384 events
- **Powershell**: 48 events
- **System**: 91 events
- **Application**: 14 events
- **Wmi**: 3 events
- **Taskscheduler**: 59 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
