# T1055.001-1: Dynamic-link Library Injection

**MITRE ATT&CK:** [T1055.001](https://attack.mitre.org/techniques/T1055/001)
**Technique:** Dynamic-link Library Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.001 -TestNumbers 1` — Process Injection via mavinject.exe

## Telemetry (101 events)
- **Sysmon**: 50 events
- **Security**: 14 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
