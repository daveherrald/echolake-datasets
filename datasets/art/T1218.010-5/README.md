# T1218.010-5: Regsvr32

**MITRE ATT&CK:** [T1218.010](https://attack.mitre.org/techniques/T1218/010)
**Technique:** Regsvr32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.010 -TestNumbers 5` — Regsvr32 Silent DLL Install Call DllRegisterServer

## Telemetry (66 events)
- **Sysmon**: 19 events
- **Security**: 12 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
