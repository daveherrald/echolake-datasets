# T1548.002-7: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 7` — Bypass UAC using sdclt DelegateExecute

## Telemetry (78 events)
- **Sysmon**: 28 events
- **Security**: 11 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
