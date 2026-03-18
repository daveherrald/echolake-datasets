# T1055.004-3: Asynchronous Procedure Call

**MITRE ATT&CK:** [T1055.004](https://attack.mitre.org/techniques/T1055/004)
**Technique:** Asynchronous Procedure Call
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.004 -TestNumbers 3` — Remote Process Injection with Go using NtQueueApcThreadEx WinAPI

## Telemetry (92 events)
- **Sysmon**: 36 events
- **Security**: 11 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
