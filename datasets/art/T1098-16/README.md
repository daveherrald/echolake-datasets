# T1098-16: Account Manipulation

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098)
**Technique:** Account Manipulation
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1098 -TestNumbers 16` — Domain Password Policy Check: Common Password Use

## Telemetry (73 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
