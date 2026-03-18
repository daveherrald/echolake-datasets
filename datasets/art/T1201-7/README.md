# T1201-7: Password Policy Discovery

**MITRE ATT&CK:** [T1201](https://attack.mitre.org/techniques/T1201)
**Technique:** Password Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1201 -TestNumbers 7` — Examine domain password policy - Windows

## Telemetry (77 events)
- **Sysmon**: 28 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
