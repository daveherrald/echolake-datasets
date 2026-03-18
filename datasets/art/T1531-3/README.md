# T1531-3: Account Access Removal

**MITRE ATT&CK:** [T1531](https://attack.mitre.org/techniques/T1531)
**Technique:** Account Access Removal
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1531 -TestNumbers 3` — Remove Account From Domain Admin Group

## Telemetry (82 events)
- **Sysmon**: 33 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
