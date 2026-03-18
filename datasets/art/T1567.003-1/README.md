# T1567.003-1: Exfiltration to Text Storage Sites

**MITRE ATT&CK:** [T1567.003](https://attack.mitre.org/techniques/T1567/003)
**Technique:** Exfiltration to Text Storage Sites
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1567.003 -TestNumbers 1` — Exfiltrate data with HTTP POST to text storage sites - pastebin.com (Windows)

## Telemetry (64 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 28 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
