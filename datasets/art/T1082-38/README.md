# T1082-38: System Information Discovery

**MITRE ATT&CK:** [T1082](https://attack.mitre.org/techniques/T1082)
**Technique:** System Information Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1082 -TestNumbers 38` — Enumerate Available Drives via gdr

## Telemetry (118 events)
- **Sysmon**: 37 events
- **Security**: 16 events
- **Powershell**: 65 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
