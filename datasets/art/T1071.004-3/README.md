# T1071.004-3: DNS

**MITRE ATT&CK:** [T1071.004](https://attack.mitre.org/techniques/T1071/004)
**Technique:** DNS
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1071.004 -TestNumbers 3` — DNS Long Domain Query

## Telemetry (314 events)
- **Sysmon**: 263 events
- **Security**: 11 events
- **Powershell**: 40 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
