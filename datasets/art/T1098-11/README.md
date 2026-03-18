# T1098-11: Account Manipulation

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098)
**Technique:** Account Manipulation
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1098 -TestNumbers 11` — Domain Password Policy Check: No Number in Password

## Telemetry (102 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
