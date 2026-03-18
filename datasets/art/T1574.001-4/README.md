# T1574.001-4: DLL

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001)
**Technique:** DLL
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.001 -TestNumbers 4` — DLL Side-Loading using the Notepad++ GUP.exe binary

## Telemetry (71 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
