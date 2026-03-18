# T1082-34: System Information Discovery

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082)
**Technique:** System Information Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1082 -TestNumbers 34` — operating system discovery

## Telemetry (120 events)
- **Sysmon**: 46 events
- **Security**: 11 events
- **Powershell**: 63 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
