# T1090.001-3: Internal Proxy

**MITRE ATT&CK:** [T1090.001](https://attack.mitre.org/techniques/T1090/001)
**Technique:** Internal Proxy
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1090.001 -TestNumbers 3` — portproxy reg key

## Telemetry (86 events)
- **Sysmon**: 35 events
- **Security**: 13 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
