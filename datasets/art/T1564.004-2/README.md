# T1564.004-2: NTFS File Attributes

**MITRE ATT&CK:** [T1564.004](https://attack.mitre.org/techniques/T1564/004)
**Technique:** NTFS File Attributes
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564.004 -TestNumbers 2` — Store file in Alternate Data Stream (ADS)

## Telemetry (83 events)
- **Sysmon**: 32 events
- **Security**: 15 events
- **Powershell**: 36 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
