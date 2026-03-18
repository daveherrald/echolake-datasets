# T1135-7: Network Share Discovery

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135)
**Technique:** Network Share Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1135 -TestNumbers 7` — Share Discovery with PowerView

## Telemetry (75 events)
- **Sysmon**: 25 events
- **Security**: 9 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
