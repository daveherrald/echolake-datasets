# T1574.001-3: DLL

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001)
**Technique:** DLL
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.001 -TestNumbers 3` — Phantom Dll Hijacking - ualapi.dll

## Telemetry (66 events)
- **Sysmon**: 20 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
