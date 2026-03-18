# T1003.003-11: NTDS

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
**Technique:** NTDS
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.003 -TestNumbers 11` — Copy NTDS in low level NTFS acquisition via fsutil

## Telemetry (121 events)
- **Sysmon**: 48 events
- **Security**: 12 events
- **Powershell**: 61 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
