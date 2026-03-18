# T1547.001-1: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001)
**Technique:** Registry Run Keys / Startup Folder
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.001 -TestNumbers 1` — Reg Key Run

## Telemetry (82 events, noise-filtered)
- **Powershell**: 34 events
- **Security**: 15 events
- **Sysmon**: 33 events

## Pipeline
Events from ACME-WS02 via Cribl Edge.
Infrastructure noise filtered (qemu-ga, Cribl, NSSM, ART framework overhead).
