# T1056.004-1: Credential API Hooking

**MITRE ATT&CK:** [T1056.004](https://attack.mitre.org/techniques/T1056/004)
**Technique:** Credential API Hooking
**Tactic(s):** collection, credential-access
**ART Test:** `Invoke-AtomicTest T1056.004 -TestNumbers 1` — Hook PowerShell TLS Encrypt/Decrypt Messages

## Telemetry (85 events)
- **Sysmon**: 36 events
- **Security**: 12 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
