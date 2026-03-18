# T1055.001-2: Dynamic-link Library Injection

**MITRE ATT&CK:** [T1055.001](https://attack.mitre.org/techniques/T1055/001)
**Technique:** Dynamic-link Library Injection
**Tactic(s):** defense-evasion, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1055.001 -TestNumbers 2` — WinPwn - Get SYSTEM shell - Bind System Shell using UsoClient DLL load technique

## Telemetry (85 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 39 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
