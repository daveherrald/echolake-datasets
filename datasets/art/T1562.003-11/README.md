# T1562.003-11: Impair Command History Logging

**MITRE ATT&CK:** [T1562.003](https://attack.mitre.org/techniques/T1562/003)
**Technique:** Impair Command History Logging
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.003 -TestNumbers 11` — Disable Windows Command Line Auditing using reg.exe

## Telemetry (70 events)
- **Sysmon**: 22 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
