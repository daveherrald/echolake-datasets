# T1135-8: Network Share Discovery

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135)
**Technique:** Network Share Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1135 -TestNumbers 8` — PowerView ShareFinder

## Telemetry (95 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
