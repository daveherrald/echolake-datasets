# T1574.009-1: Path Interception by Unquoted Path

**MITRE ATT&CK:** [T1574.009](https://attack.mitre.org/techniques/T1574/009)
**Technique:** Path Interception by Unquoted Path
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.009 -TestNumbers 1` — Execution of program.exe as service with unquoted service path

## Telemetry (77 events)
- **Sysmon**: 33 events
- **Security**: 17 events
- **Powershell**: 26 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
