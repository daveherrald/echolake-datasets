# T1098-12: Account Manipulation

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098)
**Technique:** Account Manipulation
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1098 -TestNumbers 12` — Domain Password Policy Check: No Special Character in Password

## Telemetry (83 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
