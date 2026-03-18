# T1531-1: Account Access Removal

**MITRE ATT&CK:** [T1531](https://attack.mitre.org/techniques/T1531)
**Technique:** Account Access Removal
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1531 -TestNumbers 1` — Change User Password - Windows

## Telemetry (104 events)
- **Sysmon**: 43 events
- **Security**: 27 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
