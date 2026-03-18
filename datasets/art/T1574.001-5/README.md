# T1574.001-5: DLL

**MITRE ATT&CK:** [T1574.001](https://attack.mitre.org/techniques/T1574/001)
**Technique:** DLL
**Tactic(s):** defense-evasion, persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1574.001 -TestNumbers 5` — DLL Side-Loading using the dotnet startup hook environment variable

## Telemetry (89 events)
- **Sysmon**: 37 events
- **Security**: 10 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
