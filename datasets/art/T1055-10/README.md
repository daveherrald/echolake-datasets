# T1055-10: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 10` — Remote Process Injection with Go using CreateRemoteThread WinAPI (Natively)

## Telemetry (112 events)
- **Sysmon**: 47 events
- **Security**: 12 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
