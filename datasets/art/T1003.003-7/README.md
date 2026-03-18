# T1003.003-7: NTDS

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
**Technique:** NTDS
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.003 -TestNumbers 7` — Create Volume Shadow Copy with Powershell

## Telemetry (125 events)
- **Sysmon**: 77 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
