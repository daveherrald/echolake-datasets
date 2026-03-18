# T1070.004-7: File Deletion

**MITRE ATT&CK:** [T1070.004](https://attack.mitre.org/techniques/T1070/004)
**Technique:** File Deletion
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.004 -TestNumbers 7` — Delete an entire folder - Windows PowerShell

## Telemetry (121 events)
- **Sysmon**: 55 events
- **Security**: 18 events
- **Powershell**: 46 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
