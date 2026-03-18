# T1218-3: System Binary Proxy Execution

**MITRE ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218)
**Technique:** System Binary Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218 -TestNumbers 3` — InfDefaultInstall.exe .inf Execution

## Telemetry (85 events)
- **Sysmon**: 37 events
- **Security**: 12 events
- **Powershell**: 36 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
