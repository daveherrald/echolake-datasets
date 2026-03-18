# T1555.003-6: Credentials from Web Browsers

**MITRE ATT&CK:** [T1555.003](https://attack.mitre.org/techniques/T1555/003)
**Technique:** Credentials from Web Browsers
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1555.003 -TestNumbers 6` — Simulating access to Windows Firefox Login Data

## Telemetry (100 events)
- **Sysmon**: 45 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
