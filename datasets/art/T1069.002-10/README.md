# T1069.002-10: Domain Groups

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002)
**Technique:** Domain Groups
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1069.002 -TestNumbers 10` — Enumerate Active Directory Groups with ADSISearcher

## Telemetry (96 events)
- **Sysmon**: 48 events
- **Security**: 11 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
