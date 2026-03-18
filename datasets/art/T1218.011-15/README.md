# T1218.011-15: Rundll32

**MITRE ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011)
**Technique:** Rundll32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.011 -TestNumbers 15` — Rundll32 execute command via FileProtocolHandler

## Telemetry (79 events)
- **Sysmon**: 29 events
- **Security**: 16 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
