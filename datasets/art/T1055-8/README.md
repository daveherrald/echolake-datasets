# T1055-8: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 8` — Remote Process Injection with Go using RtlCreateUserThread WinAPI

## Telemetry (118 events)
- **Sysmon**: 48 events
- **Security**: 12 events
- **Powershell**: 57 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
