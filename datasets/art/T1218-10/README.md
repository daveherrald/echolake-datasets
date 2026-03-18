# T1218-10: System Binary Proxy Execution

**MITRE ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218)
**Technique:** System Binary Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218 -TestNumbers 10` — Lolbin Gpscript logon option

## Telemetry (98 events)
- **Sysmon**: 36 events
- **Security**: 14 events
- **Powershell**: 46 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
