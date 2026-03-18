# T1218.011-1: Rundll32

**MITRE ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011)
**Technique:** Rundll32
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.011 -TestNumbers 1` — Rundll32 execute JavaScript Remote Payload With GetObject

## Telemetry (61 events)
- **Sysmon**: 15 events
- **Security**: 9 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
