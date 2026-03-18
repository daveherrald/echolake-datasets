# T1548.002-10: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 10` — UACME Bypass Method 23

## Telemetry (73 events)
- **Sysmon**: 26 events
- **Security**: 11 events
- **Powershell**: 34 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
