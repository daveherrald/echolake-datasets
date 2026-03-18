# T1546.003-1: Windows Management Instrumentation Event Subscription

**MITRE ATT&CK:** [T1546.003](https://attack.mitre.org/techniques/T1546/003)
**Technique:** Windows Management Instrumentation Event Subscription
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.003 -TestNumbers 1` — Persistence via WMI Event Subscription - CommandLineEventConsumer

## Telemetry (105 events)
- **Sysmon**: 42 events
- **Security**: 13 events
- **Powershell**: 49 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
