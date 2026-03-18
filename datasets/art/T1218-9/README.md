# T1218-9: System Binary Proxy Execution

**MITRE ATT&CK:** [T1218](https://attack.mitre.org/techniques/T1218)
**Technique:** System Binary Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218 -TestNumbers 9` — Load Arbitrary DLL via Wuauclt (Windows Update Client)

## Telemetry (74 events)
- **Sysmon**: 26 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
