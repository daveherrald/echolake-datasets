# T1036.003-3: Rename Legitimate Utilities

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003)
**Technique:** Rename Legitimate Utilities
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.003 -TestNumbers 3` — Masquerading - cscript.exe running as notepad.exe

## Telemetry (78 events)
- **Sysmon**: 30 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
