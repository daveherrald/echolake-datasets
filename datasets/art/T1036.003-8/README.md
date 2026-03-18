# T1036.003-8: Rename Legitimate Utilities

**MITRE ATT&CK:** [T1036.003](https://attack.mitre.org/techniques/T1036/003)
**Technique:** Rename Legitimate Utilities
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1036.003 -TestNumbers 8` — Malicious process Masquerading as LSM.exe

## Telemetry (74 events)
- **Sysmon**: 28 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
