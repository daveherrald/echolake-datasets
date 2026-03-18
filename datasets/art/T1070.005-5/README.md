# T1070.005-5: Network Share Connection Removal

**MITRE ATT&CK:** [T1070.005](https://attack.mitre.org/techniques/T1070/005)
**Technique:** Network Share Connection Removal
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.005 -TestNumbers 5` — Remove Administrative Shares

## Telemetry (75 events)
- **Sysmon**: 24 events
- **Security**: 22 events
- **Powershell**: 26 events
- **Wmi**: 3 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
