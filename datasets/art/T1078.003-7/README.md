# T1078.003-7: Local Accounts

**MITRE ATT&CK:** [T1078.003](https://attack.mitre.org/techniques/T1078/003)
**Technique:** Local Accounts
**Tactic(s):** defense-evasion, initial-access, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1078.003 -TestNumbers 7` — WinPwn - Loot local Credentials - Safetykatz

## Telemetry (88 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
