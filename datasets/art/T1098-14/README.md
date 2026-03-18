# T1098-14: Account Manipulation

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098)
**Technique:** Account Manipulation
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1098 -TestNumbers 14` — Domain Password Policy Check: No Lowercase Character in Password

## Telemetry (95 events)
- **Sysmon**: 47 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
