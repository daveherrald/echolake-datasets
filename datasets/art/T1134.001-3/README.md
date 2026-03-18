# T1134.001-3: Token Impersonation/Theft

**MITRE ATT&CK:** [T1134.001](https://attack.mitre.org/techniques/T1134/001)
**Technique:** Token Impersonation/Theft
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1134.001 -TestNumbers 3` — Launch NSudo Executable

## Telemetry (100 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 54 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
