# T1564.006-2: Run Virtual Instance

**MITRE ATT&CK:** [T1564.006](https://attack.mitre.org/techniques/T1564/006)
**Technique:** Run Virtual Instance
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564.006 -TestNumbers 2` — Create and start VirtualBox virtual machine

## Telemetry (88 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
