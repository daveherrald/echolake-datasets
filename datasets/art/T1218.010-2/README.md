# T1218.010-2: Regsvr32

**MITRE ATT&CK:** [T1218.010](https://attack.mitre.org/techniques/T1218/010)
**Technique:** Regsvr32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.010 -TestNumbers 2` — Regsvr32 remote COM scriptlet execution

## Telemetry (75 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
