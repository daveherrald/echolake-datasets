# T1003.002-3: Security Account Manager

**MITRE ATT&CK:** [T1003.002](https://attack.mitre.org/techniques/T1003/002)
**Technique:** Security Account Manager
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003.002 -TestNumbers 3` — esentutl.exe SAM copy

## Telemetry (246 events)
- **Sysmon**: 188 events
- **Security**: 23 events
- **Powershell**: 34 events
- **System**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
