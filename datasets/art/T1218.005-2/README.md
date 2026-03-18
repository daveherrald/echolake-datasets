# T1218.005-2: Mshta

**MITRE ATT&CK:** [T1218.005](https://attack.mitre.org/techniques/T1218/005)
**Technique:** Mshta
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1218.005 -TestNumbers 2` — Mshta executes VBScript to execute malicious command

## Telemetry (115 events)
- **Sysmon**: 56 events
- **Security**: 15 events
- **Powershell**: 44 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
