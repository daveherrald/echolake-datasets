# T1555.003-8: Credentials from Web Browsers

**MITRE ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003)
**Technique:** Credentials from Web Browsers
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555.003 -TestNumbers 8` — Decrypt Mozilla Passwords with Firepwd.py

## Telemetry (104 events)
- **Sysmon**: 44 events
- **Security**: 13 events
- **Powershell**: 45 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
