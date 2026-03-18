# T1218.010-4: Regsvr32

**MITRE ATT&CK:** [T1218.010](https://attack.mitre.org/techniques/T1218/010)
**Technique:** Regsvr32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.010 -TestNumbers 4` — Regsvr32 Registering Non DLL

## Telemetry (74 events)
- **Sysmon**: 23 events
- **Security**: 17 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
