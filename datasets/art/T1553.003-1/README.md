# T1553.003-1: SIP and Trust Provider Hijacking

**MITRE ATT&CK:** [T1553.003](https://attack.mitre.org/techniques/T1553/003)
**Technique:** SIP and Trust Provider Hijacking
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1553.003 -TestNumbers 1` — SIP (Subject Interface Package) Hijacking via Custom DLL

## Telemetry (79 events)
- **Sysmon**: 32 events
- **Security**: 17 events
- **Powershell**: 30 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
