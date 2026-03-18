# T1070.004-10: File Deletion

**MITRE ATT&CK:** [T1070.004](https://attack.mitre.org/techniques/T1070/004)
**Technique:** File Deletion
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.004 -TestNumbers 10` — Delete TeamViewer Log Files

## Telemetry (68 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 31 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
