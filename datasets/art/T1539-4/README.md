# T1539-4: Steal Web Session Cookie

**MITRE ATT&CK:** [T1539](https://attack.mitre.org/techniques/T1539)
**Technique:** Steal Web Session Cookie
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1539 -TestNumbers 4` — Steal Chrome v127+ cookies via Remote Debugging (Windows)

## Telemetry (18394 events)
- **Sysmon**: 76 events
- **Security**: 60 events
- **Powershell**: 18240 events
- **System**: 5 events
- **Application**: 7 events
- **Wmi**: 1 events
- **Taskscheduler**: 5 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
