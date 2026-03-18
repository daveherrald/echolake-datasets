# T1070.006-5: Timestomp

**MITRE ATT&CK:** [T1070.006](https://attack.mitre.org/techniques/T1070/006)
**Technique:** Timestomp
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.006 -TestNumbers 5` — Windows - Modify file creation timestamp with PowerShell

## Telemetry (72 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 36 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
