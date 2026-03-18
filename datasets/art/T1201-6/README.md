# T1201-6: Password Policy Discovery

**MITRE ATT&CK:** [T1201](https://attack.mitre.org/techniques/T1201)
**Technique:** Password Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1201 -TestNumbers 6` — Examine local password policy - Windows

## Telemetry (62 events)
- **Sysmon**: 18 events
- **Security**: 14 events
- **Powershell**: 30 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
