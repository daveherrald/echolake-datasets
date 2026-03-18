# T1548.002-4: Bypass User Account Control

**MITRE ATT&CK:** [T1548.002](https://attack.mitre.org/techniques/T1548/002)
**Technique:** Bypass User Account Control
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1548.002 -TestNumbers 4` — Bypass UAC using Fodhelper - PowerShell

## Telemetry (89 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 40 events
- **Application**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
