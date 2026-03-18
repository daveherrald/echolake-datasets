# T1218.010-1: Regsvr32

**MITRE ATT&CK:** [T1218.010](https://attack.mitre.org/techniques/T1218/010)
**Technique:** Regsvr32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.010 -TestNumbers 1` — Regsvr32 local COM scriptlet execution

## Telemetry (75 events)
- **Sysmon**: 29 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
