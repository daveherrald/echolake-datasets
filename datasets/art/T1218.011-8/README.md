# T1218.011-8: Rundll32

**MITRE ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011)
**Technique:** Rundll32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.011 -TestNumbers 8` — Execution of HTA and VBS Files using Rundll32 and URL.dll

## Telemetry (83 events)
- **Sysmon**: 33 events
- **Security**: 15 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
