# T1003-7: OS Credential Dumping

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003)
**Technique:** OS Credential Dumping
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003 -TestNumbers 7` — Send NTLM Hash with RPC Test Connection

## Telemetry (84 events)
- **Sysmon**: 34 events
- **Security**: 13 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
