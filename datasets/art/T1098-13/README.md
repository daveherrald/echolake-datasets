# T1098-13: Account Manipulation

**MITRE ATT&CK:** [T1098](https://attack.mitre.org/techniques/T1098)
**Technique:** Account Manipulation
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1098 -TestNumbers 13` — Domain Password Policy Check: No Uppercase Character in Password

## Telemetry (87 events)
- **Sysmon**: 36 events
- **Security**: 12 events
- **Powershell**: 37 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
