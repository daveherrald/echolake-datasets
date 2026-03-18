# T1036.003-6: Rename Legitimate Utilities

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003)
**Technique:** Rename Legitimate Utilities
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.003 -TestNumbers 6` — Masquerading - non-windows exe running as windows exe

## Telemetry (92 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 46 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
