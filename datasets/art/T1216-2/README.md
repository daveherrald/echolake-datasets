# T1216-2: System Script Proxy Execution

**MITRE ATT&CK:** [T1216](https://attack.mitre.org/techniques/T1216)
**Technique:** System Script Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1216 -TestNumbers 2` — manage-bde.wsf Signed Script Command Execution

## Telemetry (92 events)
- **Sysmon**: 43 events
- **Security**: 15 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
