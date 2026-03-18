# T1564.004-5: NTFS File Attributes

**MITRE ATT&CK:** [T1564.004](https://attack.mitre.org/techniques/T1564/004)
**Technique:** NTFS File Attributes
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564.004 -TestNumbers 5` — Create Hidden Directory via $index_allocation

## Telemetry (80 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
