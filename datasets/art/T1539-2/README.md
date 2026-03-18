# T1539-2: Steal Web Session Cookie

**MITRE ATT&CK:** [T1539](https://attack.mitre.org/techniques/T1539)
**Technique:** Steal Web Session Cookie
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1539 -TestNumbers 2` — Steal Chrome Cookies (Windows)

## Telemetry (89 events)
- **Sysmon**: 38 events
- **Security**: 13 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
