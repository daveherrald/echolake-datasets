# T1564-2: Hide Artifacts

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564)
**Technique:** Hide Artifacts
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564 -TestNumbers 2` — Create a Hidden User Called "$"

## Telemetry (76 events)
- **Sysmon**: 28 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
