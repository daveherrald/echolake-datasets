# T1016.001-3: Internet Connection Discovery

**MITRE ATT&CK:** [T1016.001](https://attack.mitre.org/techniques/T1016/001)
**Technique:** Internet Connection Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1016.001 -TestNumbers 3` — Check internet connection using Test-NetConnection in PowerShell (ICMP-Ping)

## Telemetry (137 events)
- **Sysmon**: 41 events
- **Security**: 17 events
- **Powershell**: 79 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
