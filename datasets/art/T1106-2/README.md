# T1106-2: Native API

**MITRE ATT&CK:** [T1106](https://attack.mitre.org/techniques/T1106)
**Technique:** Native API
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1106 -TestNumbers 2` — WinPwn - Get SYSTEM shell - Pop System Shell using CreateProcess technique

## Telemetry (119 events)
- **Sysmon**: 62 events
- **Security**: 15 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
