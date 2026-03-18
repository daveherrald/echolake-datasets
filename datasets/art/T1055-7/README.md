# T1055-7: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 7` — Process Injection with Go using EtwpCreateEtwThread WinAPI

## Telemetry (115 events)
- **Sysmon**: 46 events
- **Security**: 12 events
- **Powershell**: 57 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
