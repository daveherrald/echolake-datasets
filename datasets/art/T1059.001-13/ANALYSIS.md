# T1059.001-13: PowerShell — ATHPowerShellCommandLineParameter -Command parameter variations

## Technique Context

T1059.001 PowerShell execution is one of the most prevalent techniques used by attackers for initial access, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, and command and control. PowerShell's legitimate administrative use makes it an attractive target for living-off-the-land attacks. The detection community focuses heavily on command-line analysis, script block logging content, process ancestry chains, and behavioral patterns around PowerShell invocation methods.

This specific Atomic Red Team test examines PowerShell command-line parameter variations, particularly testing different ways to invoke the `-Command` parameter with hyphen switches. Understanding these variations is crucial because attackers often attempt to evade detection by using less common parameter formats or abbreviations that security tools might not recognize.

## What This Dataset Contains

The dataset captures a PowerShell execution chain demonstrating command-line parameter variations. The primary evidence appears in Security event 4688 showing the child PowerShell process creation:

- **Process Command Line**: `"powershell.exe" & {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -CommandParamVariation C -Execute -ErrorAction Stop}`
- **Parent Process**: PowerShell.exe (PID 30492) spawned by another PowerShell process (PID 30460/771c)
- **Child Processes**: The test executes `whoami.exe` as part of its execution flow

PowerShell event logs (EID 4104) capture script block creation for the test execution:
- Script block containing: `& {Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType Hyphen -CommandParamVariation C -Execute -ErrorAction Stop}`
- Multiple framework-related script blocks with `Set-StrictMode` calls
- PowerShell profile loading from `C:\Windows\system32\config\systemprofile\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1`

Sysmon provides comprehensive process and behavioral telemetry:
- Process creation events (EID 1) for both PowerShell processes and whoami.exe
- Image load events (EID 7) showing .NET framework DLLs and Windows Defender integration
- Process access events (EID 10) showing PowerShell accessing child processes
- Named pipe creation (EID 17) for PowerShell host communication
- File creation events (EID 11) for PowerShell startup profile data

## What This Dataset Does Not Contain

The dataset lacks the actual command-line variations being tested. While the Security logs show the PowerShell invocation with the test function call, they don't reveal what specific command-line parameter formats were executed by the `Out-ATHPowerShellCommandLineParameter` function. The PowerShell script block logs only show the test framework invocation, not the various `-Command` parameter syntaxes that were likely tested.

Missing are examples of common PowerShell parameter variations like `-c`, `-com`, `-comm`, or other abbreviated forms of `-Command` that attackers might use. The sysmon-modular configuration's include-mode filtering means we don't see Sysmon ProcessCreate events for the test PowerShell processes themselves, though Security 4688 events provide this coverage.

The PowerShell channel contains mostly framework boilerplate rather than substantive command content that would demonstrate the parameter variations being tested.

## Assessment

This dataset provides solid foundational telemetry for PowerShell execution detection but falls short of demonstrating the specific command-line parameter variations that the test was designed to showcase. The Security 4688 events with command-line logging are the strongest detection source, clearly showing PowerShell process creation with the test function invocation. The Sysmon events add valuable behavioral context around process relationships, DLL loading patterns, and file system interactions.

For building detections around PowerShell parameter variations, analysts would benefit from seeing the actual command syntax variations executed rather than just the test framework invocation. However, the parent-child process relationships and the presence of the Atomic Red Team function name provide clear indicators of testing activity.

## Detection Opportunities Present in This Data

1. **PowerShell Process Chaining**: Monitor for PowerShell processes spawning other PowerShell processes (Security 4688 where both parent and child are powershell.exe)

2. **Atomic Red Team Function Detection**: Alert on command lines containing "Out-ATHPowerShellCommandLineParameter" or similar ART function names in Security 4688 ProcessCommandLine fields

3. **PowerShell Script Block Analysis**: Detect script blocks (PowerShell 4104) containing Atomic Red Team test functions or command-line parameter testing patterns

4. **Named Pipe Creation Patterns**: Monitor Sysmon EID 17 for PowerShell host pipes following the pattern `\PSHost.[timestamp].[pid].DefaultAppDomain.powershell`

5. **Process Access to Child Processes**: Alert on PowerShell processes accessing recently created child processes with full access (Sysmon EID 10 with GrantedAccess 0x1FFFFF)

6. **Rapid PowerShell Instance Creation**: Detect multiple PowerShell processes created within short time windows, particularly when executing similar command patterns

7. **PowerShell Profile Loading**: Monitor for PowerShell profile execution from system profile directories (Sysmon EID 11 creating StartupProfileData files)

8. **Windows Defender Integration Loading**: Track PowerShell processes loading MpOAV.dll and MpClient.dll, which may indicate evasion attempts or security tool interactions
