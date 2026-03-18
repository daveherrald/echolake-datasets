# T1055-5: Process Injection

**MITRE ATT&CK:** [T1055](https://attack.mitre.org/techniques/T1055)
**Technique:** Process Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055 -TestNumbers 5` — Read-Write-Execute process Injection

## Telemetry (104 events)
- **Sysmon**: 45 events
- **Security**: 10 events
- **Powershell**: 49 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
