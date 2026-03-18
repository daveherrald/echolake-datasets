# T1110.004-4: Credential Stuffing

**MITRE ATT&CK:** [T1110.004](https://attack.mitre.org/techniques/T1110/004)
**Technique:** Credential Stuffing
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1110.004 -TestNumbers 4` — Brute Force:Credential Stuffing using Kerbrute Tool

## Telemetry (80 events)
- **Sysmon**: 26 events
- **Security**: 12 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
