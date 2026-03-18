# T1098-2: Account Manipulation

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098)
**Technique:** Account Manipulation
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1098 -TestNumbers 2` — Domain Account and Group Manipulate

## Telemetry (105 events)
- **Sysmon**: 36 events
- **Security**: 11 events
- **Powershell**: 58 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
