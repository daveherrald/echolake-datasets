# T1218-13: System Binary Proxy Execution

**MITRE ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218)
**Technique:** System Binary Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218 -TestNumbers 13` — LOLBAS CustomShellHost to Spawn Process

## Telemetry (97 events)
- **Sysmon**: 42 events
- **Security**: 14 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
