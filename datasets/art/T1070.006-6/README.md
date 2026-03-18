# T1070.006-6: Timestomp

**MITRE ATT&CK:** [T1070.006](https://attack.mitre.org/techniques/T1070/006)
**Technique:** Timestomp
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.006 -TestNumbers 6` — Windows - Modify file last modified timestamp with PowerShell

## Telemetry (82 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
