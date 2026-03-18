# T1027.013-2: Encrypted/Encoded File

**MITRE ATT&CK:** [T1027.013](https://attack.mitre.org/techniques/T1027/013)
**Technique:** Encrypted/Encoded File
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027.013 -TestNumbers 2` — Decrypt Eicar File and Write to File

## Telemetry (77 events)
- **Sysmon**: 27 events
- **Security**: 11 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
