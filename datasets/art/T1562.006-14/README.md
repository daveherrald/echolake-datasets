# T1562.006-14: Indicator Blocking

**MITRE ATT&CK:** [T1562.006](https://attack.mitre.org/techniques/T1562/006)
**Technique:** Indicator Blocking
**Tactic(s):** defense-evasion
**ART Test:** `Invoke-AtomicTest T1562.006 -TestNumbers 14` — Block Cybersecurity communication by leveraging Windows Name Resolution Policy Table

## Telemetry (74 events)
- **Sysmon**: 20 events
- **Security**: 13 events
- **Powershell**: 41 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
