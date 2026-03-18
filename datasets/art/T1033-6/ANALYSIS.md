# T1033-6: System Owner/User Discovery — System Discovery - SocGholish whoami

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries enumerate the current user context and privileges to understand their operational environment. The `whoami` utility is one of the most common tools for this purpose, providing detailed information about the current user, group memberships, and privileges. SocGholish, a prevalent JavaScript framework used in malware campaigns, often incorporates user discovery as part of its reconnaissance phase to determine if the compromised system is worth further exploitation or contains high-value targets.

Detection engineers typically focus on monitoring `whoami.exe` execution, especially when invoked with the `/all` parameter which provides comprehensive user information including SID, group memberships, and privilege enumeration. The technique becomes particularly suspicious when executed in unusual contexts, from scripted environments, or when output is redirected to files for later exfiltration.

## What This Dataset Contains

This dataset captures a PowerShell-based implementation of the SocGholish whoami discovery technique. The core activity involves a PowerShell script that generates a random filename and executes `whoami.exe /all` with output redirection.

The Security channel captures the complete process chain in Security event 4688 entries:
- Initial PowerShell execution: `"powershell.exe" & {$TokenSet = @{...} whoami.exe /all >> $env:temp\$file}`
- First `whoami.exe` execution: `"C:\Windows\system32\whoami.exe"`  
- Second `whoami.exe` execution: `"C:\Windows\system32\whoami.exe" /all`

The PowerShell channel contains detailed script execution telemetry in events 4103 and 4104, including:
- The complete PowerShell script block showing random string generation logic
- `Get-Random` cmdlet invocations for generating the random filename components
- File output operations writing the complete whoami output to `C:\Windows\TEMP\radL6I9W.tmp`
- The actual whoami output captured in PowerShell event 4103, showing full user information including "nt authority\system", group memberships, and 26 different privileges

Sysmon provides process creation events (EID 1) for both `whoami.exe` executions with complete command lines, parent-child relationships, and file creation events (EID 11) showing the output file `C:\Windows\Temp\radL6I9W.tmp` being created.

## What This Dataset Does Not Contain

The dataset does not contain evidence of the output file being accessed, read, or potentially exfiltrated after creation. There are no network connections showing data transmission, which would typically follow in a real SocGholish infection chain. The technique executes successfully without any Windows Defender blocks or access denials, indicating the behavior completed as intended.

The Sysmon ProcessCreate events for the initial PowerShell processes are missing due to sysmon-modular's include-mode filtering, though the Security 4688 events provide complete coverage of the process execution chain.

## Assessment

This dataset provides excellent coverage of the T1033 technique execution with high-fidelity telemetry across multiple data sources. The Security channel offers comprehensive process tracking with full command lines, while PowerShell logging captures the script internals and actual output data. Sysmon adds valuable process metadata and file creation evidence. The combination enables detection engineers to build robust detection logic covering process execution patterns, script content analysis, and file artifacts. The data quality is particularly strong for demonstrating how PowerShell-based discovery techniques generate rich telemetry that can be leveraged for both signature-based and behavioral detection approaches.

## Detection Opportunities Present in This Data

1. **whoami.exe execution with /all parameter** - Security 4688 events show `whoami.exe` with `/all` argument, a strong indicator for comprehensive user enumeration

2. **PowerShell script blocks containing whoami execution** - PowerShell 4104 events capture the complete script showing `whoami.exe /all >> $env:temp\$file` pattern

3. **Random filename generation patterns** - PowerShell 4103/4104 events show characteristic random string generation using Get-Random with character sets, typical of malware filename obfuscation

4. **Output redirection to temp files** - File creation events (Sysmon EID 11) combined with PowerShell cmdlet execution showing whoami output being written to temp directory files

5. **Process chain analysis** - Parent-child relationships showing PowerShell spawning whoami.exe processes, detectable through Security 4688 or Sysmon 1 events

6. **PowerShell cmdlet sequence detection** - Multiple Get-Random invocations followed by Out-File operations, indicating programmatic file creation with random names

7. **Privilege enumeration artifacts** - PowerShell 4103 events containing detailed privilege listings (SeDebugPrivilege, SeImpersonatePrivilege, etc.) indicating successful system-level user discovery

8. **File artifact correlation** - Correlation between PowerShell script execution, whoami process creation, and temp file creation with matching random filename patterns
