# T1003.003-9: NTDS

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
**Technique:** NTDS
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.003 -TestNumbers 9` — Create Volume Shadow Copy with diskshadow

## Telemetry (54 events)
- **Sysmon**: 16 events
- **Security**: 12 events
- **Powershell**: 26 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
