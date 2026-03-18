# T1070.004-5: File Deletion

**MITRE ATT&CK:** [T1070.004](https://attack.mitre.org/techniques/T1070/004)
**Technique:** File Deletion
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.004 -TestNumbers 5` — Delete an entire folder - Windows cmd

## Telemetry (79 events)
- **Sysmon**: 34 events
- **Security**: 10 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
