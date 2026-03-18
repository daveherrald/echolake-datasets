# T1137-1: Office Application Startup — Office Application Startup - Outlook as a C2

## Technique Context

T1137 (Office Application Startup) is a persistence technique where adversaries modify Office applications to execute malicious code when the application starts. This particular test (T1137.001) focuses on using Microsoft Outlook as a command and control mechanism by creating a VBA project file and modifying security settings to allow macro execution. The detection community primarily focuses on monitoring Office application configuration changes, VBA project files, and registry modifications that weaken security postures. This technique is attractive to attackers because Office applications are ubiquitous in enterprise environments and often trusted, making malicious modifications less likely to be scrutinized.

## What This Dataset Contains

This dataset captures the complete execution chain of the Office Application Startup test. The Security channel shows the full command execution via Security 4688 events, revealing PowerShell spawning cmd.exe with the command line `"cmd.exe" /c reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\Security" /v Level /t REG_DWORD /d 1 /f & mkdir %APPDATA%\Microsoft\Outlook\ >nul 2>&1 & echo "Atomic Red Team TEST" > %APPDATA%\Microsoft\Outlook\VbaProject.OTM`. The Sysmon channel captures the registry modification via Sysmon Event ID 13, showing `HKU\.DEFAULT\Software\Microsoft\Office\16.0\Outlook\Security\Level` being set to `DWORD (0x00000001)` by reg.exe (process ID 43392). Sysmon Event ID 11 shows the VBA project file creation at `C:\Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Outlook\VbaProject.OTM`. The process chain shows powershell.exe → cmd.exe → reg.exe, with Sysmon Event ID 1 capturing each process creation. The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy cmdlets and generic error handling scriptblocks).

## What This Dataset Does Not Contain

The dataset lacks the actual Office application startup that would demonstrate the persistence mechanism in action. There are no events showing Outlook.exe launching or executing the VBA project. This is expected since the test only sets up the persistence mechanism without actually triggering it. The technique's ultimate payload execution would require launching Outlook, which doesn't occur in this test. Additionally, there are no network events or additional process spawning that would indicate successful payload execution.

## Assessment

This dataset provides excellent coverage for detecting the setup phase of T1137.001. The combination of Sysmon registry monitoring (Event ID 13), file creation monitoring (Event ID 11), and process creation tracking (Event ID 1) captures all the critical artifacts. The Security channel's command-line logging provides additional context about the complete attack chain. The telemetry quality is high for building detections around the technique's preparation phase, though it doesn't demonstrate the actual persistence activation. This makes it valuable for preventive detection but less useful for understanding post-execution behaviors.

## Detection Opportunities Present in This Data

1. Registry modification to Outlook security settings - Monitor Sysmon Event ID 13 for changes to `Software\Microsoft\Office\*\Outlook\Security\Level` with value 1 (low security)

2. VBA project file creation in Outlook directories - Alert on Sysmon Event ID 11 for `.OTM` files created in `AppData\*\Microsoft\Outlook\` paths

3. Registry tool usage for Office security bypass - Detect Security Event ID 4688 for reg.exe with command lines containing "Office" and "Security\Level"

4. Command-line patterns for Outlook persistence setup - Monitor for cmd.exe executions containing both registry modifications and file operations targeting Outlook directories

5. Process chain analysis - Flag PowerShell spawning cmd.exe that subsequently runs reg.exe with Office-related registry keys

6. Bulk Office security modifications - Correlate multiple registry changes to Office security settings within short time windows
