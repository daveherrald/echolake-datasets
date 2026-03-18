# T1112-1: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 1` — Modify Registry

## Telemetry (85 events, noise-filtered)
- **Powershell**: 34 events
- **Security**: 14 events
- **Sysmon**: 37 events

## Pipeline
Events from ACME-WS02 via Cribl Edge.
Infrastructure noise filtered (qemu-ga, Cribl, NSSM, ART framework overhead).
