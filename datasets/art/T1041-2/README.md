# T1041-2: Exfiltration Over C2 Channel

**MITRE ATT&CK:** [T1041](https://attack.mitre.org/techniques/T1041)
**Technique:** Exfiltration Over C2 Channel
**Tactic(s):** exfiltration
**ART Test:** `Invoke-AtomicTest T1041 -TestNumbers 2` — Text Based Data Exfiltration using DNS subdomains

## Telemetry (92 events)
- **Sysmon**: 33 events
- **Security**: 12 events
- **Powershell**: 47 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
