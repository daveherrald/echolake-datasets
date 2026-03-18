# T1059.001-18: PowerShell — PowerShell Invoke Known Malicious Cmdlets

## Technique Context

T1059.001 PowerShell is one of the most prevalent execution techniques in modern attacks. Adversaries leverage PowerShell's extensive capabilities, administrative access, and native Windows integration to execute malicious code, download payloads, perform reconnaissance, and maintain persistence. The technique spans from simple command execution to sophisticated fileless attacks using PowerShell modules and frameworks.

This specific test simulates an attacker creating and invoking a collection of well-known malicious PowerShell cmdlets commonly associated with post-exploitation frameworks like PowerSploit and Empire. These cmdlets include credential harvesting tools (Invoke-Mimikatz, Get-GPPPassword), persistence mechanisms (Add-Persistence), reconnaissance functions (Get-Keystrokes, Invoke-Portscan), and evasion techniques (Out-EncodedCommand). Detection teams typically focus on cmdlet invocation patterns, script block content analysis, and process execution chains that indicate PowerShell abuse.

## What This Dataset Contains

The dataset captures a PowerShell execution that creates mock malicious cmdlets and then attempts to invoke them. Security event 4688 shows the actual command line: `"powershell.exe" & {$malcmdlets = "Add-Persistence", "Find-AVSignature", "Get-GPPAutologon"...` followed by a foreach loop that defines and invokes 35 different malicious cmdlet names.

However, the execution terminates prematurely with exit code 0xC0000022 (STATUS_ACCESS_DENIED), indicating Windows Defender blocked the execution. The PowerShell channel contains 41 events but they are predominantly PowerShell engine boilerplate - Set-StrictMode scriptblocks and two Set-ExecutionPolicy bypass commands. Notably absent are script block logging events (4104) that would contain the actual malicious cmdlet definitions and invocations.

Sysmon captures standard PowerShell startup activities across three separate PowerShell processes (PIDs 38156, 38940, 39880), including .NET CLR loading (EID 7), named pipe creation for PowerShell hosting (EID 17), and Windows Defender module loading. One noteworthy event is the CreateRemoteThread (EID 8) from the second PowerShell process, suggesting some form of process injection behavior before termination.

The whoami.exe execution (captured in both Security 4688 and Sysmon EID 1) appears to be a discovery command that completed successfully before the main malicious payload was blocked.

## What This Dataset Does Not Contain

This dataset lacks the core evidence that would typically accompany successful PowerShell malicious cmdlet execution. There are no PowerShell script block logging events (4104) containing the actual cmdlet definitions or invocation attempts beyond the initial execution policy changes. The malicious foreach loops that should have created function definitions for all 35 cmdlets were not captured, likely because Windows Defender terminated the process before script block logging could capture the content.

The dataset also missing network connections, file system modifications, or registry changes that would typically accompany successful execution of cmdlets like Invoke-Portscan, Get-GPPPassword, or Add-Persistence. The process injection indicators (EID 8, EID 10) suggest some advanced behavior was attempted, but the target process details are incomplete ("<unknown process>").

## Assessment

This dataset provides moderate value for detection engineering, primarily as an example of Windows Defender successfully blocking known malicious PowerShell content. The Security 4688 events with full command-line logging capture the complete attack attempt, making this excellent data for command-line based detection rules. The process execution chain and timing analysis between multiple PowerShell instances offer insights into how PowerShell-based attacks might spawn multiple processes before execution.

However, the dataset's utility is limited by the early termination. Detection engineers seeking to understand PowerShell script block analysis, AMSI integration, or post-exploitation cmdlet behavior patterns will find this dataset insufficient. The lack of successful cmdlet execution means behavioral indicators and subsequent technique chaining are absent.

The Sysmon coverage is comprehensive for process creation and image loading, though the sysmon-modular configuration's include-mode filtering explains why only specific processes like whoami.exe triggered Sysmon EID 1 events.

## Detection Opportunities Present in This Data

1. **Command-line detection for malicious PowerShell cmdlet collections** - Security 4688 contains the complete list of 35 malicious cmdlet names in a single command line, enabling signature-based detection of known post-exploitation frameworks.

2. **PowerShell process spawning patterns** - Multiple PowerShell processes (3 within 6 seconds) with similar .NET loading patterns could indicate automated or scripted execution attempts.

3. **Windows Defender blocking correlation** - Exit code 0xC0000022 combined with PowerShell execution provides a signature for blocked malicious PowerShell attempts that warrant investigation.

4. **PowerShell named pipe analysis** - Sysmon EID 17 captures PowerShell host pipe names that follow predictable patterns and could be used to identify PowerShell execution contexts.

5. **Process injection attempt detection** - Sysmon EID 8 (CreateRemoteThread) and EID 10 (ProcessAccess) from PowerShell processes indicate potential injection techniques that survived longer than the main payload.

6. **Discovery command chaining** - whoami.exe execution immediately preceding blocked PowerShell activity suggests reconnaissance phases that could trigger early warning detections.

7. **Execution policy bypass monitoring** - PowerShell 4103 events show Set-ExecutionPolicy bypass attempts that commonly precede malicious PowerShell execution.
