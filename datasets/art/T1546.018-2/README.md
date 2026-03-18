# T1546.018-2: Python Startup Hooks

**MITRE ATT&CK:** [T1546.018](https://attack.mitre.org/techniques/T1546/018)
**Technique:** Python Startup Hooks
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.018 -TestNumbers 2` — Python Startup Hook - usercustomize.py (Windows)

## Telemetry (81 events)
- **Sysmon**: 32 events
- **Security**: 16 events
- **Powershell**: 33 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
