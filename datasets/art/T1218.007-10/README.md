# T1218.007-10: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 10` — Msiexec.exe - Execute the DllUnregisterServer function of a DLL

## Telemetry (82 events)
- **Sysmon**: 28 events
- **Security**: 17 events
- **Powershell**: 37 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
