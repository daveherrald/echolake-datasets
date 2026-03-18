# T1070.005-4: Network Share Connection Removal

**MITRE ATT&CK:** [T1070.005](https://attack.mitre.org/techniques/T1070/005)
**Technique:** Network Share Connection Removal
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1070.005 -TestNumbers 4` — Disable Administrative Share Creation at Startup

## Telemetry (60 events)
- **Sysmon**: 20 events
- **Security**: 15 events
- **Powershell**: 25 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
