# T1132.001-3: Standard Encoding

**MITRE ATT&CK:** [T1132.001](https://attack.mitre.org/techniques/T1132/001)
**Technique:** Standard Encoding
**Tactic(s):** command-and-control
**ART Test:** `Invoke-AtomicTest T1132.001 -TestNumbers 3` — XOR Encoded data.

## Telemetry (93 events)
- **Sysmon**: 36 events
- **Security**: 10 events
- **Powershell**: 47 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
