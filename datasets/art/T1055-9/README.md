# T1055-9: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 9` — Remote Process Injection with Go using CreateRemoteThread WinAPI

## Telemetry (119 events)
- **Sysmon**: 47 events
- **Security**: 13 events
- **Powershell**: 56 events
- **System**: 1 events
- **Application**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
