# T1548.002-14: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 14` — UACME Bypass Method 39

## Telemetry (48 events)
- **Sysmon**: 16 events
- **Security**: 10 events
- **Powershell**: 22 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
