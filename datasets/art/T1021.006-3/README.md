# T1021.006-3: Windows Remote Management

**MITRE ATT&CK:** [T1021.006](https://attack.mitre.org/techniques/T1021/006)
**Technique:** Windows Remote Management
**Tactic(s):** lateral-movement
**ART Test:** `Invoke-AtomicTest T1021.006 -TestNumbers 3` — WinRM Access with Evil-WinRM

## Telemetry (117 events)
- **Sysmon**: 47 events
- **Security**: 12 events
- **Powershell**: 58 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
