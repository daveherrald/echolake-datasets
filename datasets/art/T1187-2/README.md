# T1187-2: Forced Authentication

**MITRE ATT&CK:** [T1187](https://attack.mitre.org/techniques/T1187)
**Technique:** Forced Authentication
**Tactic(s):** credential-access
**ART Test:** `Invoke-AtomicTest T1187 -TestNumbers 2` — WinPwn - PowerSharpPack - Retrieving NTLM Hashes without Touching LSASS

## Telemetry (103 events)
- **Sysmon**: 39 events
- **Security**: 12 events
- **Powershell**: 52 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
