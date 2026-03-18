# T1016.002-1: Wi-Fi Discovery

**MITRE ATT&CK:** [T1016.002](https://attack.mitre.org/techniques/T1016/002)
**Technique:** Wi-Fi Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1016.002 -TestNumbers 1` — Enumerate Stored Wi-Fi Profiles And Passwords via netsh

## Telemetry (74 events)
- **Sysmon**: 27 events
- **Security**: 13 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
