# T1491.001-2: Internal Defacement

**MITRE ATT&CK:** [T1491.001](https://attack.mitre.org/techniques/T1491/001)
**Technique:** Internal Defacement
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1491.001 -TestNumbers 2` — Configure LegalNoticeCaption and LegalNoticeText registry keys to display ransom message

## Telemetry (71 events)
- **Sysmon**: 28 events
- **Security**: 10 events
- **Powershell**: 33 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
