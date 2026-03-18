# T1027-4: Obfuscated Files or Information

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027)
**Technique:** Obfuscated Files or Information
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027 -TestNumbers 4` — Execution from Compressed File

## Telemetry (64 events)
- **Sysmon**: 17 events
- **Security**: 12 events
- **Powershell**: 33 events
- **Taskscheduler**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
