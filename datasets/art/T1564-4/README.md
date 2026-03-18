# T1564-4: Hide Artifacts

**MITRE ATT&CK:** [T1564](https://attack.mitre.org/techniques/T1564)
**Technique:** Hide Artifacts
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564 -TestNumbers 4` — Create and Hide a Service with sc.exe

## Telemetry (96 events)
- **Sysmon**: 44 events
- **Security**: 15 events
- **Powershell**: 36 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
