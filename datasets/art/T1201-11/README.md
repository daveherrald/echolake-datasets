# T1201-11: Password Policy Discovery

**MITRE ATT&CK:** [T1201](https://attack.mitre.org/techniques/T1201)
**Technique:** Password Policy Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1201 -TestNumbers 11` — Use of SecEdit.exe to export the local security policy (including the password policy)

## Telemetry (74 events)
- **Sysmon**: 28 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
