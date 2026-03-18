# T1134.004-1: Parent PID Spoofing

**MITRE ATT&CK:** [T1134.004](https://attack.mitre.org/techniques/T1134/004)
**Technique:** Parent PID Spoofing
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1134.004 -TestNumbers 1` — Parent PID Spoofing using PowerShell

## Telemetry (100 events)
- **Sysmon**: 36 events
- **Security**: 11 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
