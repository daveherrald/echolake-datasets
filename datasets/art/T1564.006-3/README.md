# T1564.006-3: Run Virtual Instance

**MITRE ATT&CK:** [T1564.006](https://attack.mitre.org/techniques/T1564/006)
**Technique:** Run Virtual Instance
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1564.006 -TestNumbers 3` — Create and start Hyper-V virtual machine

## Telemetry (93 events)
- **Sysmon**: 28 events
- **Security**: 12 events
- **Powershell**: 53 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
