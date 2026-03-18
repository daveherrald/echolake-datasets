# T1567.002-1: Exfiltration to Cloud Storage

**MITRE ATT&CK:** [T1567.002](https://attack.mitre.org/techniques/T1567/002)
**Technique:** Exfiltration to Cloud Storage
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1567.002 -TestNumbers 1` — Exfiltrate data with rclone to cloud Storage - Mega (Windows)

## Telemetry (124 events)
- **Sysmon**: 48 events
- **Security**: 10 events
- **Powershell**: 66 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
