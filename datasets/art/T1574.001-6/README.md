# T1574.001-6: DLL

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001)
**Technique:** DLL
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.001 -TestNumbers 6` — DLL Search Order Hijacking,DLL Sideloading Of KeyScramblerIE.DLL Via KeyScrambler.EXE

## Telemetry (120 events)
- **Sysmon**: 4 events
- **Security**: 59 events
- **Powershell**: 55 events
- **System**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
