# T1217-8: Browser Information Discovery

**MITRE ATT&CK:** [T1217](https://attack.mitre.org/techniques/T1217)
**Technique:** Browser Information Discovery
**Tactic(s):** discovery
**ART Test:** `Invoke-AtomicTest T1217 -TestNumbers 8` — List Internet Explorer Bookmarks using the command prompt

## Telemetry (66 events)
- **Sysmon**: 20 events
- **Security**: 12 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
