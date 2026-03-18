# T1078.001-1: Default Accounts

**MITRE ATT&CK:** [T1078.001](https://attack.mitre.org/techniques/T1078/001)
**Technique:** Default Accounts
**Tactic(s):** defense-evasion, initial-access, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1078.001 -TestNumbers 1` — Enable Guest account with RDP capability and admin privileges

## Telemetry (102 events)
- **Sysmon**: 37 events
- **Security**: 30 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
