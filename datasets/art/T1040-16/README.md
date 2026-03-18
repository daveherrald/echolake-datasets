# T1040-16: Network Sniffing

**MITRE ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040)
**Technique:** Network Sniffing
**Tactic(s):** credential-access, discovery
**ART Test:** `Invoke-AtomicTest T1040 -TestNumbers 16` — PowerShell Network Sniffing

## Telemetry (111 events)
- **Sysmon**: 43 events
- **Security**: 23 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
