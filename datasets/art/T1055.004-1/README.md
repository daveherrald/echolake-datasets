# T1055.004-1: Asynchronous Procedure Call

**MITRE ATT&CK:** [T1055.004](https://attack.mitre.org/techniques/T1055/004)
**Technique:** Asynchronous Procedure Call
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.004 -TestNumbers 1` — Process Injection via C#

## Telemetry (68 events)
- **Sysmon**: 24 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
