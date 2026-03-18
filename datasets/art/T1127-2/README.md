# T1127-2: Trusted Developer Utilities Proxy Execution

**MITRE ATT&CK:** [T1127](https://attack.mitre.org/techniques/T1127)
**Technique:** Trusted Developer Utilities Proxy Execution
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1127 -TestNumbers 2` — Lolbin Jsc.exe compile javascript to dll

## Telemetry (72 events)
- **Sysmon**: 24 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
