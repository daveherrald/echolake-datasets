# T1547.008-1: LSASS Driver

**MITRE ATT&CK:** [T1547.008](https://attack.mitre.org/techniques/T1547/008)
**Technique:** LSASS Driver
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1547.008 -TestNumbers 1` — Modify Registry to load Arbitrary DLL into LSASS - LsaDbExtPt

## Telemetry (84 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
