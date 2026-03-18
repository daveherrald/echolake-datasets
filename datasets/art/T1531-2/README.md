# T1531-2: Account Access Removal

**MITRE ATT&CK:** [T1531](https://attack.mitre.org/techniques/T1531)
**Technique:** Account Access Removal
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1531 -TestNumbers 2` — Delete User - Windows

## Telemetry (70 events)
- **Sysmon**: 25 events
- **Security**: 18 events
- **Powershell**: 27 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
