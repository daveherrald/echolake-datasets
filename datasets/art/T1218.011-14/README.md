# T1218.011-14: Rundll32

**MITRE ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011)
**Technique:** Rundll32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.011 -TestNumbers 14` — Running DLL with .init extension and function

## Telemetry (67 events)
- **Sysmon**: 21 events
- **Security**: 16 events
- **Powershell**: 30 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
