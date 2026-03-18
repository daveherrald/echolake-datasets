# T1106-3: Native API

**MITRE ATT&CK:** [T1106](https://attack.mitre.org/techniques/T1106)
**Technique:** Native API
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1106 -TestNumbers 3` — WinPwn - Get SYSTEM shell - Bind System Shell using CreateProcess technique

## Telemetry (68 events)
- **Sysmon**: 30 events
- **Security**: 10 events
- **Powershell**: 28 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
