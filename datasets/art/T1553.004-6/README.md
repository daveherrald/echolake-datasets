# T1553.004-6: Install Root Certificate

**MITRE ATT&CK:** [T1553.004](https://attack.mitre.org/techniques/T1553/004)
**Technique:** Install Root Certificate
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1553.004 -TestNumbers 6` — Install root CA on Windows with certutil

## Telemetry (97 events)
- **Sysmon**: 48 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
