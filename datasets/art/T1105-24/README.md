# T1105-24: Ingress Tool Transfer

**MITRE ATT&CK:** [T1105](https://attack.mitre.org/techniques/T1105)
**Technique:** Ingress Tool Transfer
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1105 -TestNumbers 24` — Lolbas replace.exe use to copy UNC file

## Telemetry (70 events)
- **Sysmon**: 22 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
