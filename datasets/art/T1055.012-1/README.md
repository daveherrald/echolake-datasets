# T1055.012-1: Process Hollowing

**MITRE ATT&CK:** [T1055.012](https://attack.mitre.org/techniques/T1055/012)
**Technique:** Process Hollowing
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.012 -TestNumbers 1` — Process Hollowing using PowerShell

## Telemetry (109 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
