# T1542.001-1: System Firmware

**MITRE ATT&CK:** [T1542.001](https://attack.mitre.org/techniques/T1542/001)
**Technique:** System Firmware
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1542.001 -TestNumbers 1` — UEFI Persistence via Wpbbin.exe File Creation

## Telemetry (89 events)
- **Sysmon**: 37 events
- **Security**: 13 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
