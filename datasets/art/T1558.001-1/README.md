# T1558.001-1: Golden Ticket

**MITRE ATT&CK:** [T1558.001](https://attack.mitre.org/techniques/T1558/001)
**Technique:** Golden Ticket
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.001 -TestNumbers 1` — Crafting Active Directory golden tickets with mimikatz

## Telemetry (60 events)
- **Sysmon**: 17 events
- **Security**: 9 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
