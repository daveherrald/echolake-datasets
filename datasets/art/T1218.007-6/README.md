# T1218.007-6: Msiexec

**MITRE ATT&CK:** [T1218.007](https://attack.mitre.org/techniques/T1218/007)
**Technique:** Msiexec
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.007 -TestNumbers 6` — WMI Win32_Product Class - Execute Local MSI file with embedded VBScript

## Telemetry (131 events)
- **Sysmon**: 58 events
- **Security**: 16 events
- **Powershell**: 51 events
- **Application**: 6 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
