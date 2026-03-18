# T1069.002-5: Domain Groups

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002)
**Technique:** Domain Groups
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1069.002 -TestNumbers 5` — Find local admins on all machines in domain (PowerView)

## Telemetry (75 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
