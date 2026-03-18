# T1134.001-2: Token Impersonation/Theft

**MITRE ATT&CK:** [T1134.001](https://attack.mitre.org/techniques/T1134/001)
**Technique:** Token Impersonation/Theft
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1134.001 -TestNumbers 2` — `SeDebugPrivilege` token duplication

## Telemetry (81 events)
- **Sysmon**: 27 events
- **Security**: 10 events
- **Powershell**: 44 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
