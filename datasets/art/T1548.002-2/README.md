# T1548.002-2: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 2` — Bypass UAC using Event Viewer (PowerShell)

## Telemetry (89 events)
- **Sysmon**: 38 events
- **Security**: 11 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
