# T1218.007-7: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 7` — WMI Win32_Product Class - Execute Local MSI file with an embedded DLL

## Telemetry (146 events)
- **Sysmon**: 63 events
- **Security**: 20 events
- **Powershell**: 57 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
