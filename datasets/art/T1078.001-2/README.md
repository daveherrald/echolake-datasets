# T1078.001-2: Default Accounts

**MITRE ATT&CK:** [T1078.001](https://attack.mitre.org/techniques/T1078/001)
**Technique:** Default Accounts
**Tactic(s):** defense-evasion, initial-access, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1078.001 -TestNumbers 2` — Activate Guest Account

## Telemetry (63 events)
- **Sysmon**: 18 events
- **Security**: 14 events
- **Powershell**: 31 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
