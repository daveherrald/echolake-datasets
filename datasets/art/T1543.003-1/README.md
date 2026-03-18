# T1543.003-1: Windows Service

**MITRE ATT&CK:** [T1543.003](https://attack.mitre.org/techniques/T1543/003)
**Technique:** Windows Service
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1543.003 -TestNumbers 1` — Modify Fax service to run PowerShell

## Telemetry (76 events)
- **Sysmon**: 28 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
