# T1134.002-2: Create Process with Token

**MITRE ATT&CK:** [T1134.002](https://attack.mitre.org/techniques/T1134/002)
**Technique:** Create Process with Token
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1134.002 -TestNumbers 2` — WinPwn - Get SYSTEM shell - Pop System Shell using Token Manipulation technique

## Telemetry (113 events)
- **Sysmon**: 52 events
- **Security**: 10 events
- **Powershell**: 51 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
