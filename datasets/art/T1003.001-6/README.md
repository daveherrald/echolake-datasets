# T1003.001-6: LSASS Memory

**MITRE ATT&CK:** [T1003.001](https://attack.mitre.org/techniques/T1003/001)
**Technique:** LSASS Memory
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.001 -TestNumbers 6` — Offline Credential Theft With Mimikatz

## Telemetry (83 events, noise-filtered)
- **Powershell**: 41 events
- **Security**: 9 events
- **Sysmon**: 33 events

## Pipeline
Events from ACME-WS02 via Cribl Edge.
Infrastructure noise filtered (qemu-ga, Cribl, NSSM, ART framework overhead).
