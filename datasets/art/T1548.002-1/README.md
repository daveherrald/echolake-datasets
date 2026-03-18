# T1548.002-1: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 1` — Bypass UAC using Event Viewer (cmd)

## Telemetry (107 events)
- **Sysmon**: 51 events
- **Security**: 22 events
- **Powershell**: 30 events
- **Application**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
