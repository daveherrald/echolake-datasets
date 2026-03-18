# T1112-57: Modify Registry

**MITRE ATT&CK:** [T1112](https://attack.mitre.org/techniques/T1112)
**Technique:** Modify Registry
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1112 -TestNumbers 57` — Snake Malware Registry Blob

## Telemetry (97 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
