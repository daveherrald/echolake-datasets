# T1124-4: System Time Discovery

**MITRE ATT&CK:** [T1124](https://attack.mitre.org/techniques/T1124)
**Technique:** System Time Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1124 -TestNumbers 4` — System Time Discovery W32tm as a Delay

## Telemetry (74 events)
- **Sysmon**: 26 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
