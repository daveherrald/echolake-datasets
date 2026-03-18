# T1003-2: OS Credential Dumping

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003)
**Technique:** OS Credential Dumping
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003 -TestNumbers 2` — Credential Dumping with NPPSpy

## Telemetry (118 events)
- **Sysmon**: 50 events
- **Security**: 10 events
- **Powershell**: 58 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
