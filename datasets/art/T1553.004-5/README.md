# T1553.004-5: Install Root Certificate

**MITRE ATT&CK:** [T1553.004](https://attack.mitre.org/techniques/T1553/004)
**Technique:** Install Root Certificate
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1553.004 -TestNumbers 5` — Install root CA on Windows

## Telemetry (82 events)
- **Sysmon**: 26 events
- **Security**: 11 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
