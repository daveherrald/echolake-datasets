# Currentis Operation Black Start

A fictional ICS/OT intrusion at the fictional utility **Currentis Energy** (domain `currentis.local`), captured as replayable synthetic security telemetry for detection engineering, threat hunting, and SOC-investigation training. The scenario fuses a 2026-era agentic AI initial-access vector with a classic vendor-account IT-to-OT pivot, and ends not with a bang but with quiet pre-positioning on a wind-farm turbine controller.

Everything here is synthetic, generated in an isolated lab with RFC1918 addressing. **GLACIER DRIFT** is a fictional threat actor modeled on, not attributed to, public reporting. No real organization, vendor, or target is involved.

## Overview

- **~172K events** across 7 data sources
- **Multi-host** Windows Active Directory plus a SCADA jump host on an OT segment
- **Background activity**: 7 employee personas generating roughly 3.5 hours of realistic office baseline (email, Slack, browsing, file access) as the haystack
- **Attack**: an 8-stage kill chain from agentic prompt-injection through credential theft, an IT-to-OT pivot, OT reconnaissance, low-and-slow exfiltration, and a log clear
- **Built-in threat-intel hook**: the C2 address is a publicly documented Cobalt Strike indicator (`121.43.243.13`), so a low-confidence "outbound to a possible C2 indicator" detection fires on replay

## Scenario

A state-aligned actor uses a prompt injection against an AI coding assistant running on an engineer's workstation to seed a living-off-the-land intrusion. The actor harvests a cached turbine-vendor remote-access credential, rides that account from IT into OT, and quietly pre-positions on the wind-farm SCADA jump host ahead of a turbine control-loop manipulation it never fires. The detection story is two deliberate blind spots with the domain controller catching the hop between them: patient zero is an EDR-free machine-learning workstation, the OT jump host is unmonitored by design, but the lateral movement authenticates through an instrumented domain controller.

## Kill Chain

| # | Stage | Host / persona | ATT&CK (Enterprise) | ATT&CK (ICS) |
|---|-------|----------------|---------------------|--------------|
| 0 | Prompt-injection initial access. A poisoned "NERC CIP-010 baseline diff" document reaches Rachel's mailbox; her AI coding assistant reads it to summarize and runs a base64 PowerShell stager. | Rachel Chen (`rchen`), CURRENTIS-WS-RACHEL | T1566, T1204, T1059.001 | n/a |
| 1 | Recon (LOTL). `whoami`, `gpresult`, `net group`, `nltest`, AD queries, hidden in normal troubleshooting habit. | WS-RACHEL to DC01 | T1087.002, T1482 | n/a |
| 2 | Beacon. A masqueraded binary beacons to the C2 every ~60 seconds. | WS-RACHEL | T1071.001, T1036 | n/a |
| 3 | Credential access. An LSASS read harvests the cached turbine-vendor credential and a dormant service account. | WS-RACHEL | T1003.001, T1078 | n/a |
| 4 | IT-to-OT pivot. RDP from Rachel's box to the SCADA jump host using the stolen `helixgrid-svc` account. The account, not the host, is the anomaly. | WS-RACHEL to SCADA-JH-02 | T1021.001, T1078, T1133 | T0859, T0822 |
| 5 | OT recon / control-loop mapping. Enumerate engineering software, pull Unit 3 turbine config and alarm/setpoint data. No change yet. | SCADA-JH-02 | T1083, T1005 | T0888 |
| 6 | Exfil (low and slow). Turbine config and alarm data trickle out the C2 channel, staged small. | SCADA-JH-02 | T1041, T1567 | T0882 |
| 7 | The surprise. Stage a Unit 3 setpoint-modification capability and a modified control profile, but do not fire it. Clear the Security log and go dormant. | SCADA-JH-02 | T1053.005, T1070.001 | T0831 (staged) |

## Data Sources

| File | Events | Description |
|------|--------|-------------|
| microsoft_winevtlog.jsonl.gz | 93,152 | Windows Sysmon, Security, and PowerShell events across all hosts (attack + baseline) |
| zeek_dns.jsonl.gz | 45,235 | Zeek DNS logs (name-resolution baseline) |
| zeek_conn.jsonl.gz | 30,918 | Zeek connection logs (includes the C2 beacon and exfil) |
| linux_syslog.jsonl.gz | 1,247 | Linux syslog (proxy, Zeek sensors, baseline hosts) |
| zeek_http.jsonl.gz | 794 | Zeek HTTP logs (includes the HTTP C2 beacon requests) |
| slack_messages.jsonl.gz | 398 | Slack persona chatter (human baseline, needle-in-haystack) |
| exchange_message_tracking.jsonl.gz | 14 | Exchange message tracking (includes the poisoned NERC CIP-010 document) |

All files are gzipped JSON Lines in a lakehouse bronze shape, with `_event_time` and `_ingest_time` timestamp fields and a `data` payload.

## MITRE ATT&CK Coverage

| Tactic | Techniques |
|--------|------------|
| Initial Access | T1566, T1078, T1133 |
| Execution | T1204, T1059.001 |
| Discovery | T1087.002, T1482, T1083 |
| Command and Control | T1071.001 |
| Defense Evasion | T1036, T1070.001 |
| Credential Access | T1003.001 |
| Lateral Movement | T1021.001 |
| Collection | T1005 |
| Exfiltration | T1041, T1567 |
| Persistence | T1053.005 |

**ATT&CK for ICS:** T0859 (Valid Accounts), T0822 (External Remote Services), T0888 (Remote System Information Discovery), T0882 (Theft of Operational Information), T0831 (Manipulation of Control, staged but not fired).

## AI and Compliance Framing

- **OWASP LLM01 (Prompt Injection)** and **OWASP MAESTRO Layer 4 (agentic tool abuse)** for the stage-0 initial access through the AI coding assistant.
- **NERC CIP-010** (configuration baseline, the lure document) and **NERC CIP-003** (vendor electronic remote access, the pivot account) for the OT compliance angle.

## Environment

- **Domain**: currentis.local, VLAN 192.168.4.0/24
- **Patient zero**: CURRENTIS-WS-RACHEL (192.168.4.233), a deliberately EDR-free machine-learning workstation
- **OT target**: CURRENTIS-SCADA-JH-02 (192.168.4.244), an unmonitored OT jump host with seeded Unit 3 turbine configuration files
- **Instrumentation**: Sysmon (SwiftOnSecurity config), Windows audit policy with command-line logging and SACLs on the OT file paths, PowerShell script block logging
- **Network monitoring**: Zeek (conn, dns, http), Squid proxy
- **Collection**: Cribl Edge

## Threat-Intel Indicator

The internal Sliver C2 address was rewritten to `121.43.243.13`, a publicly documented Cobalt Strike indicator (HTTP beacon, `/push` URI, Aliyun ASN, first seen 2026-05-22, labeled "Possible Cobaltstrike C2 IP" in open C2 intel feeds). 202 events were rewritten across the Sysmon network-connect events and the Zeek conn/dns/http logs so that a low-confidence threat-intel detection fires on replay and gives an investigation a concrete starting pivot.

## Known Limitations

This is synthetic data and carries a few honest caveats:

- EDR alert telemetry is not included. In the source lab the EDR covered only the domain controller and Exchange host, which is also why patient zero is a realistic blind spot.
- The scripted implant and recon stages execute under a machine account, while the stage-0 agent-to-PowerShell chain is attributed to `rchen`.
- The final exfil (~02:45 UTC) lands slightly after the log clear (~02:30 UTC).

## Replay

The dataset carries an EchoLake `dataset.yaml` with the ATT&CK mapping, an environment block, and dual-timestamp replay defaults. EchoLake rebases the bounded capture window so the last event lands at "now," which lets "last 24 hours" style hunting prompts work against the replayed data without date math.

## License

CC0 1.0 Universal (Public Domain Dedication). See [LICENSE](../../LICENSE).
