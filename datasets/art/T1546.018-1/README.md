# T1546.018-1: Python Startup Hooks

**MITRE ATT&CK:** [T1546.018](https://attack.mitre.org/techniques/T1546/018)
**Technique:** Python Startup Hooks
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.018 -TestNumbers 1` — Python Startup Hook - atomic_hook.pth (Windows)

## Telemetry (1101 events)
- **Sysmon**: 1037 events
- **Security**: 22 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
