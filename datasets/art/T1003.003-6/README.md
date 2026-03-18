# T1003.003-6: NTDS

**MITRE ATT&CK:** [T1003.003](https://attack.mitre.org/techniques/T1003/003)
**Technique:** NTDS
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.003 -TestNumbers 6` — Create Volume Shadow Copy remotely (WMI) with esentutl

## Telemetry (104 events)
- **Sysmon**: 42 events
- **Security**: 20 events
- **Powershell**: 38 events
- **Application**: 4 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
