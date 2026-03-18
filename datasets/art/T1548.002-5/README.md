# T1548.002-5: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 5` — Bypass UAC using ComputerDefaults (PowerShell)

## Telemetry (81 events)
- **Sysmon**: 29 events
- **Security**: 11 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
