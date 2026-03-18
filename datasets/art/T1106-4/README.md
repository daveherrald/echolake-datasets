# T1106-4: Native API

**MITRE ATT&CK:** [T1106](https://attack.mitre.org/techniques/T1106)
**Technique:** Native API
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1106 -TestNumbers 4` — WinPwn - Get SYSTEM shell - Pop System Shell using NamedPipe Impersonation technique

## Telemetry (216 events)
- **Sysmon**: 117 events
- **Security**: 35 events
- **Powershell**: 61 events
- **System**: 3 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
