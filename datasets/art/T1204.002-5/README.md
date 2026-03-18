# T1204.002-5: Malicious File

**MITRE ATT&CK:** [T1204.002](https://attack.mitre.org/techniques/T1204/002)
**Technique:** Malicious File
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1204.002 -TestNumbers 5` — Office launching .bat file from AppData

## Telemetry (145 events)
- **Sysmon**: 37 events
- **Security**: 11 events
- **Powershell**: 97 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
