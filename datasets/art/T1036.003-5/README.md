# T1036.003-5: Rename Legitimate Utilities

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003)
**Technique:** Rename Legitimate Utilities
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.003 -TestNumbers 5` — Masquerading - powershell.exe running as taskhostw.exe

## Telemetry (96 events)
- **Sysmon**: 43 events
- **Security**: 14 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
