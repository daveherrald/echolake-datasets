# T1078.003-13: Local Accounts

**MITRE ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003)
**Technique:** Local Accounts
**Tactic(s):** defense-evasion, initial-access, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1078.003 -TestNumbers 13` — Use PsExec to elevate to NT Authority\SYSTEM account

## Telemetry (65 events)
- **Sysmon**: 20 events
- **Security**: 11 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
