# T1059.001-16: PowerShell — ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments

## Technique Context

T1059.001 PowerShell execution is one of the most prevalent techniques attackers use on Windows systems. PowerShell's `-EncodedCommand` parameter allows execution of Base64-encoded commands, which serves multiple attack purposes: bypassing basic string-based detections, evading command-line logging restrictions, and obscuring malicious intent from casual inspection. This specific test focuses on parameter variations (`-E` as shorthand for `-EncodedCommand`) combined with encoded arguments, representing a common obfuscation pattern where both the command structure and arguments are encoded.

Detection engineers particularly focus on PowerShell command-line patterns, encoded command usage, and parent-child process relationships. The ATH (Atomic Test Test framework) PowerShell CommandLineParameter framework generates realistic attack scenarios that test detection coverage against parameter variations commonly used by adversaries.

## What This Dataset Contains

This dataset captures the execution of the Out-ATHPowerShellCommandLineParameter function with `-EncodedCommandParamVariation E` (using `-E` shorthand) and `-UseEncodedArguments` with `-EncodedArgumentsParamVariation EncodedArguments`. The key evidence includes:

**Process Creation Chain**: Security Event 4688 shows powershell.exe spawning another powershell.exe with command line `"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -EncodedCommandParamVariation E -UseEncodedArguments -EncodedArgumentsParamVariation EncodedArguments -Execute -ErrorAction Stop}`, followed by whoami.exe execution.

**Sysmon Process Events**: Sysmon EID 1 captures the same process creations, including whoami.exe (PID 33840) with parent powershell.exe, and a second powershell.exe process (PID 34908) that represents the encoded command execution.

**PowerShell Activity**: The PowerShell channel contains 45 events, but these are primarily test framework boilerplate showing Set-StrictMode operations and Set-ExecutionPolicy Bypass calls. The actual encoded command execution content is not captured in script block logging, suggesting the encoded payload may have been minimal or the logging didn't capture the decoded content.

**Process Access Events**: Sysmon EID 10 shows PowerShell accessing both the whoami.exe and child powershell.exe processes with full access rights (0x1FFFFF), indicating normal process management behavior.

## What This Dataset Does Not Contain

The dataset lacks the actual encoded PowerShell command that was executed. While we see the test framework calling the ATH function, the resulting encoded command line that would normally be visible in process creation events is absent. This suggests either:

1. The encoded command execution was intercepted or blocked
2. The test generated a minimal payload
3. The actual malicious command simulation didn't complete successfully

There are no network connections, file writes with suspicious content, or registry modifications that would typically accompany meaningful PowerShell attack scenarios. The PowerShell script block logs don't contain the decoded command content, which is a significant gap for understanding what the encoded execution attempted to accomplish.

## Assessment

This dataset provides good foundational telemetry for detecting PowerShell execution patterns and parent-child relationships, but limited insight into encoded command detection specifically. The process creation events in both Security and Sysmon logs clearly show PowerShell spawning behavior, which is valuable for behavioral detection. However, the absence of the actual encoded command makes it less useful for testing encoded PowerShell detection rules.

The Windows Defender integration is evident through the MpClient.dll and MpOAV.dll loads in PowerShell processes, but there's no indication of blocking behavior. This dataset would be stronger if it included examples of the actual encoded commands being executed, even if they were benign test payloads.

## Detection Opportunities Present in This Data

1. **PowerShell Process Spawning Detection**: Security 4688 and Sysmon EID 1 show powershell.exe creating child powershell.exe processes, indicating potential process injection or encoded command execution patterns.

2. **PowerShell Execution Policy Bypass**: PowerShell EID 4103 shows `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass`, a common technique preparation step.

3. **ATH Framework Detection**: Command lines containing "Out-ATHPowerShellCommandLineParameter" provide clear indicators of attack simulation tools being executed.

4. **PowerShell Module Loading Patterns**: Sysmon EID 7 shows System.Management.Automation.ni.dll loading, indicating PowerShell runtime initialization that could trigger on encoded command execution.

5. **Process Access Correlation**: Sysmon EID 10 events showing PowerShell accessing newly created processes can indicate command execution or process manipulation behaviors.

6. **PowerShell Pipe Creation**: Sysmon EID 17 shows named pipe creation by PowerShell processes, which can be associated with inter-process communication during command execution.

7. **Suspicious Parent-Child Relationships**: Detection of powershell.exe spawning whoami.exe or additional powershell.exe instances from non-interactive contexts.
