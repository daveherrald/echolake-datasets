# T1133-1: External Remote Services

**MITRE ATT&CK:** [T1133](https://attack.mitre.org/techniques/T1133)
**Technique:** External Remote Services
**Tactic(s):** initial-access, persistence
**ART Test:** `Invoke-AtomicTest T1133 -TestNumbers 1` — Running Chrome VPN Extensions via the Registry 2 vpn extension

## Telemetry (115 events)
- **Sysmon**: 36 events
- **Security**: 20 events
- **Powershell**: 57 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
