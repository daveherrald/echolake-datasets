# T1552.001-5: Credentials In Files

**MITRE ATT&CK:** [T1552.001](https://attack.mitre.org/techniques/T1552/001)
**Technique:** Credentials In Files
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1552.001 -TestNumbers 5` — Access unattend.xml

## Telemetry (70 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
