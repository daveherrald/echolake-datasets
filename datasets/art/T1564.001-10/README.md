# T1564.001-10: Hidden Files and Directories

**MITRE ATT&CK:** [T1564.001](https://attack.mitre.org/techniques/T1564/001)
**Technique:** Hidden Files and Directories
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564.001 -TestNumbers 10` — Create Windows System File with powershell

## Telemetry (96 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 50 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
