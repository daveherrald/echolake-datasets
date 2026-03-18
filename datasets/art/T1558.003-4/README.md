# T1558.003-4: Kerberoasting

**MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003)
**Technique:** Kerberoasting
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1558.003 -TestNumbers 4` — Request A Single Ticket via PowerShell

## Telemetry (81 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 44 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
