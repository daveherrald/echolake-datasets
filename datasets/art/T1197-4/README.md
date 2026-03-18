# T1197-4: BITS Jobs

**MITRE ATT&CK:** [T1197](https://attack.mitre.org/techniques/T1197)
**Technique:** BITS Jobs
**Tactic(s):** defense-evasion, persistence
**ART Test:** `Invoke-AtomicTest T1197 -TestNumbers 4` — Bits download using desktopimgdownldr.exe (cmd)

## Telemetry (73 events)
- **Sysmon**: 25 events
- **Security**: 14 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
