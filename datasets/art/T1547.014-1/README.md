# T1547.014-1: Active Setup

**MITRE ATT&CK:** [T1547.014](https://attack.mitre.org/techniques/T1547/014)
**Technique:** Active Setup
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.014 -TestNumbers 1` — HKLM - Add atomic_test key to launch executable as part of user setup

## Telemetry (95 events)
- **Sysmon**: 41 events
- **Security**: 14 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
