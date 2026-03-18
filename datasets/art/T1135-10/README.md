# T1135-10: Network Share Discovery

**MITRE ATT&CK:** [T1135](https://attack.mitre.org/techniques/T1135)
**Technique:** Network Share Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1135 -TestNumbers 10` — Network Share Discovery via dir command

## Telemetry (72 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
