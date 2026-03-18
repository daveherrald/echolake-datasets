# T1003-5: OS Credential Dumping

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003)
**Technique:** OS Credential Dumping
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003 -TestNumbers 5` — Retrieve Microsoft IIS Service Account Credentials Using AppCmd (using config)

## Telemetry (93 events)
- **Sysmon**: 38 events
- **Security**: 10 events
- **Powershell**: 45 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
