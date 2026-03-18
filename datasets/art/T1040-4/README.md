# T1040-4: Network Sniffing

**MITRE ATT&CK:** [T1040](https://attack.mitre.org/techniques/T1040)
**Technique:** Network Sniffing
**Tactic(s):** credential-access, discovery
**ART Test:** `Invoke-AtomicTest T1040 -TestNumbers 4` — Packet Capture Windows Command Prompt

## Telemetry (71 events)
- **Sysmon**: 26 events
- **Security**: 11 events
- **Powershell**: 34 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
