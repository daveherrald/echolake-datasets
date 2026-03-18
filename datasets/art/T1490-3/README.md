# T1490-3: Inhibit System Recovery

**MITRE ATT&CK:** [T1490](https://attack.mitre.org/techniques/T1490)
**Technique:** Inhibit System Recovery
**Tactic(s):** impact
**ART Test:** `Invoke-AtomicTest T1490 -TestNumbers 3` — Windows - wbadmin Delete Windows Backup Catalog

## Telemetry (99 events)
- **Sysmon**: 33 events
- **Security**: 26 events
- **Powershell**: 34 events
- **System**: 1 events
- **Application**: 3 events
- **Wmi**: 2 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
