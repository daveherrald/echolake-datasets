# T1003.003-2: NTDS

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
**Technique:** NTDS
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.003 -TestNumbers 2` — Copy NTDS.dit from Volume Shadow Copy

## Telemetry (65 events)
- **Sysmon**: 15 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
