# T1055.011-1: Extra Window Memory Injection

**MITRE ATT&CK:** [T1055.011](https://attack.mitre.org/techniques/T1055/011)
**Technique:** Extra Window Memory Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.011 -TestNumbers 1` — Process Injection via Extra Window Memory (EWM) x64 executable

## Telemetry (102 events)
- **Sysmon**: 38 events
- **Security**: 18 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
