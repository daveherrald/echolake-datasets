# T1219-14: Remote Access Tools — Splashtop Streamer Execution

## Technique Context

T1219 covers adversary use of legitimate remote access tools to maintain persistent access and perform remote operations on compromised systems. While these tools have legitimate business purposes, attackers often abuse them because they blend into normal network traffic, are trusted by security controls, and provide reliable command and control channels. Popular targets include TeamViewer, AnyDesk, LogMeIn, VNC, and Splashtop.

Detection teams focus on unusual installations, executions from unexpected locations, network connections to unknown remote access service domains, and process behaviors that deviate from typical administrative usage patterns. The challenge is distinguishing malicious usage from legitimate remote administration without generating excessive false positives.

## What This Dataset Contains

This dataset captures a failed attempt to execute Splashtop Streamer software through PowerShell. The key events show:

**Process Creation Chain:** Security event 4688 shows PowerShell spawning another PowerShell instance with the command line `"powershell.exe" & {Start-Process -FilePath \"C:Program Files (x86)\Splashtop\Splashtop Remote\Server\SRServer.exe\"}`. Sysmon EID 1 captures the same process creation with full command line details.

**PowerShell Error Handling:** The PowerShell operational log (EID 4103, 4100) shows the Start-Process cmdlet failing with "This command cannot be run due to the error: The system cannot find the file specified." The script block logging (EID 4104) captures the exact command: `Start-Process -FilePath "C:Program Files (x86)\Splashtop\Splashtop Remote\Server\SRServer.exe"`.

**Discovery Activity:** Sysmon EID 1 shows execution of `whoami.exe` for system owner/user discovery, a common reconnaissance activity that often accompanies remote access tool deployment.

**Process Access Events:** Sysmon EID 10 captures PowerShell accessing both the whoami.exe and child PowerShell processes with full access rights (0x1FFFFF), demonstrating typical process injection detection capabilities.

**File System Activity:** Sysmon EID 11 shows PowerShell creating startup profile data files, indicating normal PowerShell initialization behavior.

## What This Dataset Does Not Contain

The dataset lacks the actual Splashtop software installation or successful execution because the target file path doesn't exist on the system. There are no network connections to Splashtop infrastructure, no service installations, no registry modifications for persistence, and no file downloads or installations that would normally accompany remote access tool deployment.

The Sysmon ProcessCreate events don't capture the initial PowerShell processes due to the include-mode filtering configuration that only captures known-suspicious patterns. The PowerShell channel contains mostly test framework boilerplate and error handling rather than the core technique execution.

## Assessment

This dataset provides excellent telemetry for detecting attempted remote access tool execution through PowerShell, even when the attempt fails. The combination of Security 4688 events with command-line logging, PowerShell script block logging, and Sysmon process creation events offers multiple detection angles. The error conditions actually make this more valuable for detection engineering, as they show how failed execution attempts still generate useful forensic evidence.

The PowerShell operational logs are particularly strong, capturing both the cmdlet invocation and the specific error message. This demonstrates that even unsuccessful attacks leave substantial traces that defenders can leverage.

## Detection Opportunities Present in This Data

1. **Remote Access Tool Command Lines:** Security EID 4688 and Sysmon EID 1 command lines containing paths to remote access software executables like "Splashtop", "TeamViewer", "AnyDesk", or similar tools in typical installation directories.

2. **PowerShell Start-Process with Remote Access Tools:** PowerShell EID 4103 showing Start-Process cmdlet invocations with FilePath parameters pointing to remote access tool executables.

3. **PowerShell Script Block Remote Tool Execution:** EID 4104 script blocks containing Start-Process commands or direct execution of remote access tool binaries.

4. **Failed Remote Access Tool Execution:** PowerShell EID 4100 error messages indicating "system cannot find the file specified" for remote access tool paths, suggesting attempted execution of non-existent tools.

5. **Process Access Patterns:** Sysmon EID 10 showing PowerShell processes accessing newly created processes with full rights, particularly when combined with remote access tool execution attempts.

6. **Discovery Activity Correlation:** Sysmon EID 1 showing whoami.exe execution in temporal proximity to remote access tool execution attempts, indicating reconnaissance activities.

7. **PowerShell Process Spawning:** Security EID 4688 showing PowerShell spawning child PowerShell processes with command lines containing remote access tool execution commands.
