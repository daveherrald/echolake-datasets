# T1562.003-12: Impair Command History Logging

**MITRE ATT&CK:** [T1562.003](https://attack.mitre.org/techniques/T1562/003)
**Technique:** Impair Command History Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.003 -TestNumbers 12` — Disable Windows Command Line Auditing using Powershell Cmdlet

## Telemetry (87 events)
- **Sysmon**: 37 events
- **Security**: 12 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
