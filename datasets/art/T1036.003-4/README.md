# T1036.003-4: Rename Legitimate Utilities

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003)
**Technique:** Rename Legitimate Utilities
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.003 -TestNumbers 4` — Masquerading - wscript.exe running as svchost.exe

## Telemetry (76 events)
- **Sysmon**: 33 events
- **Security**: 13 events
- **Powershell**: 30 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
