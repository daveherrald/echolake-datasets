# T1566.001-1: Spearphishing Attachment

**MITRE ATT&CK:** [T1566.001](https://attack.mitre.org/techniques/T1566/001)
**Technique:** Spearphishing Attachment
**Tactic(s):** initial-access
**ART Test:** `Invoke-AtomicTest T1566.001 -TestNumbers 1` — Download Macro-Enabled Phishing Attachment

## Telemetry (55 events)
- **Sysmon**: 3 events
- **Security**: 10 events
- **Powershell**: 42 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
