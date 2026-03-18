# T1070.004-11: File Deletion

**MITRE ATT&CK:** [T1070.004](https://attack.mitre.org/techniques/T1070/004)
**Technique:** File Deletion
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.004 -TestNumbers 11` — Clears Recycle bin via rd

## Telemetry (72 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
