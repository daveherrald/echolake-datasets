# T1003.003-10: NTDS

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
**Technique:** NTDS
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.003 -TestNumbers 10` — Copy NTDS in low level NTFS acquisition via MFT parsing

## Telemetry (136 events)
- **Sysmon**: 59 events
- **Security**: 14 events
- **Powershell**: 63 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
