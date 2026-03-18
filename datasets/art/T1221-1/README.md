# T1221-1: Template Injection

**MITRE ATT&CK:** [T1221](https://attack.mitre.org/techniques/T1221)
**Technique:** Template Injection
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1221 -TestNumbers 1` — WINWORD Remote Template Injection

## Telemetry (65 events)
- **Sysmon**: 17 events
- **Security**: 19 events
- **Powershell**: 27 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
