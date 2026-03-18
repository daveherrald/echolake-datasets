# T1548.002-19: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 19` — WinPwn - UAC Bypass ccmstp technique

## Telemetry (115 events)
- **Sysmon**: 48 events
- **Security**: 10 events
- **Powershell**: 57 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
