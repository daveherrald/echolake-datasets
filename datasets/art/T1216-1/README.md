# T1216-1: System Script Proxy Execution

**MITRE ATT&CK:** [T1216](https://attack.mitre.org/techniques/T1216)
**Technique:** System Script Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1216 -TestNumbers 1` — SyncAppvPublishingServer Signed Script PowerShell Command Execution

## Telemetry (124 events)
- **Sysmon**: 58 events
- **Security**: 18 events
- **Powershell**: 48 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
