# T1027.013-1: Encrypted/Encoded File

**MITRE ATT&CK:** [T1027.013](https://attack.mitre.org/techniques/T1027/013)
**Technique:** Encrypted/Encoded File
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027.013 -TestNumbers 1` — Decode Eicar File and Write to File

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
