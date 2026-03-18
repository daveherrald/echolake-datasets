# T1003-3: OS Credential Dumping

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003)
**Technique:** OS Credential Dumping
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003 -TestNumbers 3` — Dump svchost.exe to gather RDP credentials

## Telemetry (102 events)
- **Sysmon**: 43 events
- **Security**: 20 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
