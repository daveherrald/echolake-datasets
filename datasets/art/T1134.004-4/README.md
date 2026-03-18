# T1134.004-4: Parent PID Spoofing

**MITRE ATT&CK:** [T1134.004](https://attack.mitre.org/techniques/T1134/004)
**Technique:** Parent PID Spoofing
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1134.004 -TestNumbers 4` — Parent PID Spoofing - Spawn from svchost.exe

## Telemetry (115 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 69 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
