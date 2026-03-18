# T1057-9: Process Discovery

**MITRE ATT&CK:** [T1057](https://attack.mitre.org/techniques/T1057)
**Technique:** Process Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1057 -TestNumbers 9` — Launch Taskmgr from cmd to View running processes

## Telemetry (100 events)
- **Sysmon**: 35 events
- **Security**: 29 events
- **Powershell**: 34 events
- **Application**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
