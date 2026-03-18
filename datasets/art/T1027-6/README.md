# T1027-6: Obfuscated Files or Information

**MITRE ATT&CK:** [T1027](https://attack.mitre.org/techniques/T1027)
**Technique:** Obfuscated Files or Information
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1027 -TestNumbers 6` — DLP Evasion via Sensitive Data in VBA Macro over HTTP

## Telemetry (88 events)
- **Sysmon**: 31 events
- **Security**: 10 events
- **Powershell**: 47 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
