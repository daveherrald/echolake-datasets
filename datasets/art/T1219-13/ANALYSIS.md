# T1219-13: Remote Access Tools — Splashtop Execution

## Technique Context

T1219 (Remote Access Tools) represents adversaries' use of legitimate remote access software to maintain persistence and conduct activities on remote systems. RATs like Splashtop, TeamViewer, AnyDesk, and others are widely used in enterprise environments, making their malicious use difficult to distinguish from legitimate administration. Attackers often leverage these tools during the command and control phase to blend in with normal business operations while maintaining persistent access to compromised systems. The detection community focuses on identifying unusual RAT installations, executions from unexpected contexts, connections to suspicious endpoints, and RAT usage patterns inconsistent with organizational baselines.

## What This Dataset Contains

This dataset captures an attempt to execute Splashtop Remote Client that ultimately fails due to the software not being installed. The key telemetry includes:

**Process Execution Chain:** Security 4688 events show the progression from parent powershell.exe (PID 22780) executing `Start-Process` with command line `"powershell.exe" & {Start-Process \""${env:programfiles(x86)}\Splashtop\Splashtop Remote\Client for STP\strwinclt.exe\""}` and launching child powershell.exe (PID 25404).

**PowerShell Script Block:** PowerShell 4104 events capture the actual execution attempt: `& {Start-Process "${env:programfiles(x86)}\Splashtop\Splashtop Remote\Client for STP\strwinclt.exe"}` with the environment variable expansion showing the target path `C:\Program Files (x86)\Splashtop\Splashtop Remote\Client for STP\strwinclt.exe`.

**Error Indication:** PowerShell 4100 error event shows "This command cannot be run due to the error: The system cannot find the file specified" and PowerShell 4103 TerminatingError confirms the failure with "InvalidOperationException,Microsoft.PowerShell.Commands.StartProcessCommand".

**Sysmon Telemetry:** Extensive EID 1 (Process Create) events for the PowerShell processes involved, EID 7 (Image Load) events showing .NET runtime loading, EID 10 (Process Access) events, EID 11 (File Create) for PowerShell profile data, and EID 17 (Pipe Create) for PowerShell named pipes.

## What This Dataset Does Not Contain

The dataset lacks the actual RAT execution since Splashtop is not installed on the test system. There are no network connections (Sysmon EID 3), no Splashtop process creation, no RAT-specific registry modifications, and no file operations related to Splashtop installation or configuration. The failure occurs at the Start-Process cmdlet level before any Splashtop-specific activity could begin. Additionally, since the technique fails immediately, there are no indicators of successful RAT deployment such as service installations, persistence mechanisms, or C2 communications that would typically be associated with T1219.

## Assessment

This dataset provides moderate value for detection engineering focused on attempted RAT deployments rather than successful ones. The telemetry is excellent for detecting PowerShell-based attempts to launch remote access tools, even when they fail. The combination of Security 4688 command-line logging and PowerShell script block logging (4104) provides clear visibility into the execution attempt and target RAT path. However, for comprehensive T1219 detection development, datasets showing successful RAT installation and operation would be more valuable. This data is particularly useful for detecting reconnaissance attempts or failed deployment phases of RAT-based attacks.

## Detection Opportunities Present in This Data

1. **PowerShell RAT Launch Detection** - Monitor PowerShell 4104 script blocks for `Start-Process` commands targeting known RAT executable paths like `*\Splashtop\*\strwinclt.exe`, `*\TeamViewer\*`, or `*\AnyDesk\*`

2. **RAT Path Enumeration** - Detect attempts to execute files in common RAT installation directories through Security 4688 command lines containing `${env:programfiles*}\Splashtop\`, `%ProgramFiles%\TeamViewer`, or similar RAT paths

3. **Failed RAT Execution** - Correlate PowerShell 4100 error events with message "The system cannot find the file specified" when preceded by Start-Process cmdlet attempts targeting RAT binaries

4. **Process Chain Analysis** - Monitor for powershell.exe parent-child relationships where the child process command line contains RAT executable paths, even when execution fails

5. **PowerShell CommandInvocation Monitoring** - Track PowerShell 4103 events for Start-Process parameter bindings with FilePath values pointing to remote access tool executables

6. **Environment Variable Expansion** - Detect PowerShell script blocks using environment variable expansion (`${env:programfiles*}`) to construct paths to remote access software installations
