# T1546.009-1: AppCert DLLs

**MITRE ATT&CK:** [T1546.009](https://attack.mitre.org/techniques/T1546/009)
**Technique:** AppCert DLLs
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.009 -TestNumbers 1` — Create registry persistence via AppCert DLL

## Telemetry (113 events)
- **Sysmon**: 52 events
- **Security**: 12 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
