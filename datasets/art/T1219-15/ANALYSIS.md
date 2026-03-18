# T1219-15: Remote Access Tools — Microsoft App Quick Assist Execution

## Technique Context

T1219 Remote Access Tools covers adversary use of legitimate remote administration software to establish persistent remote access to victim systems. Microsoft Quick Assist is a built-in Windows application that enables remote screen sharing and system control for technical support scenarios. The detection community focuses on monitoring for unexpected remote access tool deployments, particularly when initiated from command line interfaces or scripts rather than through normal user interactions. Quick Assist is particularly interesting because it's pre-installed on Windows systems and can be launched programmatically, making it a potential living-off-the-land technique for maintaining persistence or facilitating lateral movement.

## What This Dataset Contains

This dataset captures an attempt to launch Microsoft Quick Assist via PowerShell using the `Start-Process` cmdlet with the shell URI `shell:AppsFolder\MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App`. The key telemetry includes:

**PowerShell Evidence (EID 4104, 4103, 4100):**
- Script block creation for the command: `Start-Process "shell:AppsFolder\MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App"`
- Command invocation logging showing the Start-Process cmdlet with the Quick Assist shell URI
- PowerShell error (EID 4100): "This command cannot be run due to the error: The system cannot find the file specified"

**Process Creation (Security EID 4688, Sysmon EID 1):**
- Parent PowerShell process spawning a child PowerShell process with command line: `"powershell.exe" & {Start-Process "shell:AppsFolder\MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App"}`
- Additional whoami.exe execution for system discovery

**Supporting Telemetry:**
- Multiple Sysmon EID 7 events showing .NET Framework DLL loads in PowerShell processes
- Sysmon EID 10 process access events showing PowerShell accessing child processes
- Sysmon EID 17 named pipe creation events for PowerShell inter-process communication

## What This Dataset Does Not Contain

The Quick Assist application itself never launched successfully. The PowerShell error indicates the shell URI could not resolve to an executable application, likely because Quick Assist is not properly installed or configured on this domain-joined enterprise workstation. Consequently, the dataset lacks:

- Network connections to Microsoft's Quick Assist infrastructure
- Quick Assist process creation or related application telemetry
- Remote desktop protocol traffic or screen sharing indicators
- User interface events that would accompany successful Quick Assist launch

The technique execution failed at the application launch stage, so while we have excellent visibility into the attempt, we don't see the post-exploitation behaviors that would follow successful Quick Assist deployment.

## Assessment

This dataset provides excellent visibility into programmatic attempts to launch Quick Assist through PowerShell, even when the launch fails. The combination of PowerShell script block logging, command-line auditing, and Sysmon process creation events creates a comprehensive detection surface. The failure case is actually valuable for detection engineering because it shows how attempts to abuse Quick Assist will appear in logs regardless of whether the application successfully launches. The PowerShell error messages provide clear indicators of the specific technique being attempted.

## Detection Opportunities Present in This Data

1. **PowerShell script block detection** for commands containing "shell:AppsFolder" URI schemes combined with Quick Assist application identifiers
2. **Command-line monitoring** for Start-Process cmdlets targeting Quick Assist through shell URI syntax (`MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App`)
3. **Process tree analysis** detecting PowerShell parent processes spawning child PowerShell instances with Quick Assist launch parameters
4. **PowerShell error correlation** monitoring for "system cannot find the file specified" errors when combined with Quick Assist shell URI attempts
5. **Named pipe monitoring** for PowerShell inter-process communication patterns associated with remote access tool deployment attempts
6. **Behavioral clustering** of Quick Assist launch attempts combined with system discovery commands (whoami execution in same process tree)
