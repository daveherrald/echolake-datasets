# T1069.002-9: Domain Groups

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002)
**Technique:** Domain Groups
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1069.002 -TestNumbers 9` — Enumerate Active Directory Groups with Get-AdGroup

## Telemetry (96 events)
- **Sysmon**: 38 events
- **Security**: 11 events
- **Powershell**: 45 events
- **Application**: 1 events
- **Taskscheduler**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
