# T1078.003-1: Local Accounts

**MITRE ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003)
**Technique:** Local Accounts
**Tactic(s):** defense-evasion, initial-access, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1078.003 -TestNumbers 1` — Create local account with admin privileges

## Telemetry (79 events)
- **Sysmon**: 23 events
- **Security**: 22 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
