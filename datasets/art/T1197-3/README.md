# T1197-3: BITS Jobs

**MITRE ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197)
**Technique:** BITS Jobs
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1197 -TestNumbers 3` — Persist, Download, & Execute

## Telemetry (88 events)
- **Sysmon**: 31 events
- **Security**: 22 events
- **Powershell**: 35 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
