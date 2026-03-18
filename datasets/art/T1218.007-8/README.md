# T1218.007-8: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 8` — WMI Win32_Product Class - Execute Local MSI file with an embedded EXE

## Telemetry (128 events)
- **Sysmon**: 54 events
- **Security**: 18 events
- **Powershell**: 50 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
