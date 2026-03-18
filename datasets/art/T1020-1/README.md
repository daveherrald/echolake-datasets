# T1020-1: Automated Exfiltration

**MITRE ATT&CK:** [T1020](https://attack.mitre.org/techniques/T1020)
**Technique:** Automated Exfiltration
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1020 -TestNumbers 1` — IcedID Botnet HTTP PUT

## Telemetry (88 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
