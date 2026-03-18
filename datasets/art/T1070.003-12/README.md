# T1070.003-12: Clear Command History

**MITRE ATT&CK:** [T1070.003](https://attack.mitre.org/techniques/T1070/003)
**Technique:** Clear Command History
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.003 -TestNumbers 12` — Clear Powershell History by Deleting History File

## Telemetry (72 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
