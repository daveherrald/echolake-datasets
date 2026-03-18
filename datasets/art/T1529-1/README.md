# T1529-1: System Shutdown/Reboot

**MITRE ATT&CK:** [T1529](https://attack.mitre.org/techniques/T1529)
**Technique:** System Shutdown/Reboot
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1529 -TestNumbers 1` — Shutdown System - Windows

## Telemetry (147 events)
- **Sysmon**: 44 events
- **Security**: 12 events
- **Powershell**: 91 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
