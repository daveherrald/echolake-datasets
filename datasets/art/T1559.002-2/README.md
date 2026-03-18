# T1559.002-2: Dynamic Data Exchange

**MITRE ATT&CK:** [T1559.002](https://attack.mitre.org/techniques/T1559/002)
**Technique:** Dynamic Data Exchange
**Tactic(s):** execution
**ART Test:** `Invoke-AtomicTest T1559.002 -TestNumbers 2` — Execute PowerShell script via Word DDE

## Telemetry (84 events)
- **Sysmon**: 29 events
- **Security**: 21 events
- **Powershell**: 32 events
- **System**: 1 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
