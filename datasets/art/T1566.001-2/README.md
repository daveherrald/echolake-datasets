# T1566.001-2: Spearphishing Attachment

**MITRE ATT&CK:** [T1566.001](https://attack.mitre.org/techniques/T1566/001)
**Technique:** Spearphishing Attachment
**Tactic(s):** initial-access
**ART Test:** `Invoke-AtomicTest T1566.001 -TestNumbers 2` — Word spawned a command shell and used an IP address in the command line

## Telemetry (108 events)
- **Sysmon**: 1 events
- **Security**: 10 events
- **Powershell**: 97 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
