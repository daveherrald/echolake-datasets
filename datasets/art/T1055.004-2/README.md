# T1055.004-2: Asynchronous Procedure Call

**MITRE ATT&CK:** [T1055.004](https://attack.mitre.org/techniques/T1055/004)
**Technique:** Asynchronous Procedure Call
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.004 -TestNumbers 2` — EarlyBird APC Queue Injection in Go

## Telemetry (93 events)
- **Sysmon**: 36 events
- **Security**: 12 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
