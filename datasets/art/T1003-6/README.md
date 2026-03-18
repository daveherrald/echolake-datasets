# T1003-6: OS Credential Dumping

**MITRE ATT&CK:** [T1003](https://attack.mitre.org/techniques/T1003)
**Technique:** OS Credential Dumping
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1003 -TestNumbers 6` — Dump Credential Manager using keymgr.dll and rundll32.exe

## Telemetry (105 events)
- **Sysmon**: 40 events
- **Security**: 21 events
- **Powershell**: 37 events
- **Application**: 1 events
- **Taskscheduler**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
