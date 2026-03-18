# T1564-3: Hide Artifacts

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564)
**Technique:** Hide Artifacts
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564 -TestNumbers 3` — Create an "Administrator " user (with a space on the end)

## Telemetry (94 events)
- **Sysmon**: 46 events
- **Security**: 10 events
- **Powershell**: 38 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
