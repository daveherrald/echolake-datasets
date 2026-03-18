# T1070.006-7: Timestomp

**MITRE ATT&CK:** [T1070.006](https://attack.mitre.org/techniques/T1070/006)
**Technique:** Timestomp
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.006 -TestNumbers 7` — Windows - Modify file last access timestamp with PowerShell

## Telemetry (91 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
