# T1134.005-1: SID-History Injection

**MITRE ATT&CK:** [T1134.005](https://attack.mitre.org/techniques/T1134/005)
**Technique:** SID-History Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1134.005 -TestNumbers 1` — Injection SID-History with mimikatz

## Telemetry (71 events)
- **Sysmon**: 26 events
- **Security**: 10 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
