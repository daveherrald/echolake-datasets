# T1546.003-2: Windows Management Instrumentation Event Subscription

**MITRE ATT&CK:** [T1546.003](https://attack.mitre.org/techniques/T1546/003)
**Technique:** Windows Management Instrumentation Event Subscription
**Tactic(s):** persistence, privilege-escalation
**ART Test:** `Invoke-AtomicTest T1546.003 -TestNumbers 2` — Persistence via WMI Event Subscription - ActiveScriptEventConsumer

## Telemetry (88 events)
- **Sysmon**: 40 events
- **Security**: 10 events
- **Powershell**: 37 events
- **Wmi**: 1 events

## Pipeline Verification
VM event counts verified against source. Infrastructure noise filtered. Only events from ACME-WS02.
