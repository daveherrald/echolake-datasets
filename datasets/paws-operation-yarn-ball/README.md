# PAWS Operation Yarn Ball: Scripted Intrusion Prelude

This package is a March 18, 2026 capture from the Pawsitive Vibes Windows Active Directory lab. It contains background host and network activity across seven PAWS systems plus a short scripted intrusion prelude on PAWS-WS02.

The stable dataset identifier remains `paws-operation-yarn-ball`. Version 1.1.0 narrows the public description and ATT&CK coverage to behavior supported by the bundled telemetry.

## What the telemetry supports

The scripted sequence runs from 00:17:51 through 00:20:29 UTC on PAWS-WS02. The capture contains:

- QEMU guest-agent process trees launching repeated PowerShell sessions that write scenario files to `C:\Windows\Temp`.
- PowerShell script block logging for Defender exclusions targeting `C:\Windows\Temp` and `patch-kb5041234.exe`.
- Two `node.exe` launches of `openclaw_sim.js`, followed by `whoami`, `hostname`, `ipconfig`, `systeminfo`, `net user`, `net group`, and `net view` discovery commands.
- Command lines that attempt an HTTPS diagnostic upload and binary retrieval.
- Registration of the `SecurityPatchRecovery` scheduled task and execution of the staged `patch-kb5041234.exe` binary.
- One outbound `powershell.exe` TCP connection to the lab host on port 9090.

Six scripts named for later scenario stages are evidenced as file writes only. The package has no execution evidence for those scripts. It also has no supporting process, service, file, or event-log records for credential dumping, WinRM or PsExec lateral movement, bulk file encryption, or Windows event-log clearing.

Recurring proxy and HTTP records to the lab host on port 8080 are also present. Endpoint telemetry attributes the direct connections to a Python service on PAWS-DC01, so this package does not label them as a Sliver beacon from PAWS-WS02.

An Attack Flow covering only the evidenced prelude is attached (`attack_flow.json`, stages S1-S7 from the Defender exclusions through the staged-binary execution). A formal flow for the intended full operation would overstate the evidence in this capture, so the flow stops where the evidence does and says so in its final stage.

## Capture summary

- **1,295,883 replayable events** across 12 bundled sources.
- **Capture window:** 2026-03-18 00:00:00 through 14:48:57 UTC.
- **Windows hosts:** PAWS-DC01, PAWS-EXEC01, PAWS-IT01, and PAWS-WS01 through PAWS-WS04.
- **Windows telemetry:** Sysmon, Security, PowerShell, WMI, Task Scheduler, System, and Application logs.
- **Network telemetry:** Squid proxy plus Zeek connection, DNS, and HTTP logs. The network files include PAWS and neighboring lab-segment traffic selected by the extraction filter.

## Data Sources

| File | Events | Description |
|------|--------|-------------|
| `sysmon.xml.gz` | 685,735 | Sysmon operational events from all seven PAWS hosts |
| `security.xml.gz` | 66,986 | Windows Security logon, process, and audit events |
| `powershell.xml.gz` | 2,582 | PowerShell operational events, including script block logging |
| `wmi.xml.gz` | 20,351 | WMI activity events |
| `taskscheduler.xml.gz` | 4,904 | Task Scheduler operational events |
| `system.xml.gz` | 2,208 | Windows System events |
| `application.xml.gz` | 2,148 | Windows Application events |
| `wineventlog_other.xml.gz` | 6 | Other Windows event channels |
| `proxylog.log.gz` | 63,320 | Squid proxy access records |
| `zeek_conn.jsonl.gz` | 326,812 | Zeek connection records |
| `zeek_dns.jsonl.gz` | 80,972 | Zeek DNS records |
| `zeek_http.jsonl.gz` | 39,859 | Zeek HTTP records |

## Evidenced MITRE ATT&CK coverage

| Tactic | Techniques |
|--------|------------|
| Execution | T1059.001 PowerShell, T1059.003 Windows Command Shell, T1059.007 JavaScript/JScript, T1053.005 Scheduled Task |
| Persistence | T1053.005 Scheduled Task |
| Privilege Escalation | T1053.005 Scheduled Task |
| Defense Evasion | T1685 Disable or Modify Tools (carried as T1562.001 before the ATT&CK v20 renumber), T1036.005 Match Legitimate Resource Name or Location |
| Command and Control | T1071.001 Application Layer Protocol: Web Protocols (contact attempts only), T1105 Ingress Tool Transfer |
| Discovery | T1082 System Information Discovery, T1016 System Network Configuration Discovery, T1033 System Owner/User Discovery, T1087.001 Local Account Discovery, T1069.002 Domain Groups Discovery, T1018 Remote System Discovery |

Use this package to evaluate scripted staging, defense impairment, discovery, scheduled-task persistence, and mixed background-activity analytics. It is not a full-chain ransomware, lateral-movement, or log-clearing evaluation dataset.

## Detection Rules

One entry-point [Sigma](https://sigmahq.io/) rule lives in
[`rules/sigma/`](rules/sigma/): the PowerShell script block setting Defender
exclusions for the staging directory and patch binary, the first scripted
action of the prelude. It passes `sigma check` and converts to Splunk, Loki,
and Lucene. The rest of the scripted sequence is investigation material
rather than rules, and the recurring port 8080 traffic is not flagged because
the capture attributes it to a Python service on PAWS-DC01. The manifest's `cases` section pairs this rule with its expected disposition and benign explanations as eval ground truth. See the
[Sigma rules README](rules/sigma/README.md) for the verification table with
dataset match counts and the field-mapping caveats.

## Environment

- **Domain**: pawsitivevibes.local
- **Hosts**: PAWS-DC01, PAWS-EXEC01, PAWS-IT01, and PAWS-WS01 through PAWS-WS04
- **Instrumentation**: Sysmon 15.15, Windows process and logon auditing, and PowerShell script block and module logging
- **Network monitoring**: Zeek and a Squid-format proxy service
- **Collection**: Cribl Edge

## License

CC0 1.0 Universal (Public Domain Dedication). See [LICENSE](../../LICENSE).
