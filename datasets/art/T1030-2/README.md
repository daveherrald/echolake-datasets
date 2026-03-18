# T1030-2: Data Transfer Size Limits

**MITRE ATT&CK:** [T1030](https://attack.mitre.org/techniques/T1030)
**Technique:** Data Transfer Size Limits
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1030 -TestNumbers 2` — Network-Based Data Transfer in Small Chunks

## Telemetry (75 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
