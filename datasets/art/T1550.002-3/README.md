# T1550.002-3: Pass the Hash

**MITRE ATT&CK:** [T1550.002](https://attack.mitre.org/techniques/T1550/002)
**Technique:** Pass the Hash
**Tactic(s):** defense-evasion, lateral-movement
**ART Test:** `Invoke-AtomicTest T1550.002 -TestNumbers 3` — Invoke-WMIExec Pass the Hash

## Telemetry (107 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
