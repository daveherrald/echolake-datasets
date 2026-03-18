# T1546.013-1: PowerShell Profile

**MITRE ATT&CK:** [T1546.013](https://attack.mitre.org/techniques/T1546/013)
**Technique:** PowerShell Profile
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.013 -TestNumbers 1` — Append malicious start-process cmdlet

## Telemetry (113 events)
- **Sysmon**: 57 events
- **Security**: 14 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
