# T1562.006-9: Indicator Blocking

**MITRE ATT&CK:** [T1562.006](https://attack.mitre.org/techniques/T1562/006)
**Technique:** Indicator Blocking
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.006 -TestNumbers 9` — LockBit Black - Disable the ETW Provider of Windows Defender -Powershell

## Telemetry (86 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
