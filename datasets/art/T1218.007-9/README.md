# T1218.007-9: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 9` — Msiexec.exe - Execute the DllRegisterServer function of a DLL

## Telemetry (103 events)
- **Sysmon**: 48 events
- **Security**: 15 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
