# T1218-15: System Binary Proxy Execution

**MITRE ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218)
**Technique:** System Binary Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218 -TestNumbers 15` — LOLBAS Msedge to Spawn Process

## Telemetry (107 events)
- **Sysmon**: 49 events
- **Security**: 18 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
