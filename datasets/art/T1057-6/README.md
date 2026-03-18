# T1057-6: Process Discovery

**MITRE ATT&CK:** [T1057](https://attack.mitre.org/techniques/T1057)
**Technique:** Process Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1057 -TestNumbers 6` — Discover Specific Process - tasklist

## Telemetry (80 events)
- **Sysmon**: 31 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
