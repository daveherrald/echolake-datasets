# T1105-37: Ingress Tool Transfer

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105)
**Technique:** Ingress Tool Transfer
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1105 -TestNumbers 37` — Windows pull file using sftp.exe

## Telemetry (110 events)
- **Sysmon**: 50 events
- **Security**: 15 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
