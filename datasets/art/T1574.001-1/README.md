# T1574.001-1: DLL

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001)
**Technique:** DLL
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.001 -TestNumbers 1` — DLL Search Order Hijacking - amsi.dll

## Telemetry (90 events)
- **Sysmon**: 42 events
- **Security**: 12 events
- **Powershell**: 36 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
