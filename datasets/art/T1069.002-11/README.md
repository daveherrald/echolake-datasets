# T1069.002-11: Domain Groups

**MITRE ATT&CK:** [T1069.002](https://attack.mitre.org/techniques/T1069/002)
**Technique:** Domain Groups
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1069.002 -TestNumbers 11` — Get-ADUser Enumeration using UserAccountControl flags (AS-REP Roasting)

## Telemetry (92 events)
- **Sysmon**: 36 events
- **Security**: 11 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
