# T1113-8: Screen Capture — Windows Screen Capture (CopyFromScreen)

## Technique Context

T1113 Screen Capture is a Collection technique where adversaries capture screenshots to gather visual information about systems, applications, or data displayed on screens. This is commonly used for reconnaissance, credential harvesting from login prompts, or exfiltrating sensitive information displayed in applications. The detection community focuses on monitoring for screen capture API calls, unusual graphics library usage, and file creation patterns consistent with screenshot operations. This specific test implements screen capture using .NET's System.Windows.Forms CopyFromScreen method via PowerShell, representing a common approach used by both legitimate tools and malware.

## What This Dataset Contains

This dataset captures a successful PowerShell-based screen capture execution. The core activity occurs in Security event 4688, showing PowerShell spawning with the complete command line: `"powershell.exe" & {Add-Type -AssemblyName System.Windows.Forms $screen = [Windows.Forms.SystemInformation]::VirtualScreen $bitmap = New-Object Drawing.Bitmap $screen.Width, $screen.Height $graphic = [Drawing.Graphics]::FromImage($bitmap) $graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size) $bitmap.Save(\""$env:TEMP\T1113.png\"")}`

The PowerShell script block logging in events 4104 and 4103 captures the technique implementation details, including the Add-Type cmdlet loading System.Windows.Forms assembly and the New-Object cmdlet creating Drawing.Bitmap objects with specific dimensions (1024x768). The technique successfully creates a screenshot file, evidenced by Sysmon event 11 showing file creation at `C:\Windows\Temp\T1113.png`.

Sysmon captures extensive .NET framework DLL loading through events 7, including mscoree.dll, mscoreei.dll, clr.dll, and System.Management.Automation.ni.dll. The dataset also shows Sysmon event 1 process creation for both whoami.exe and the screen capture PowerShell instance, plus event 10 process access events with full access rights (0x1FFFFF) to child processes.

## What This Dataset Does Not Contain

The dataset lacks application-level telemetry showing what was actually captured in the screenshot - we only see the file creation, not the visual content. There are no ETW events from graphics subsystems that might provide additional context about screen buffer access. The technique executed successfully without any blocking from Windows Defender, so we don't see defense evasion artifacts or access denied errors. Network telemetry is absent since this test performs local file storage rather than exfiltration. Registry modifications related to graphics settings or display configuration are not present in this execution.

## Assessment

This dataset provides excellent telemetry for detecting PowerShell-based screen capture techniques. The combination of Security 4688 command-line logging, PowerShell script block logging (4104), and Sysmon file creation (11) creates multiple high-fidelity detection opportunities. The PowerShell logs capture both the assembly loading (Add-Type System.Windows.Forms) and the specific .NET classes used (Drawing.Bitmap, CopyFromScreen), providing precise technical indicators. The file creation event gives defenders the output artifact location. This represents comprehensive coverage of the technique's execution chain from process creation through file output.

## Detection Opportunities Present in This Data

1. PowerShell command lines containing "System.Windows.Forms" and "CopyFromScreen" method calls in Security 4688 events
2. PowerShell script block logging (4104) showing Add-Type cmdlet loading System.Windows.Forms assembly
3. PowerShell script block logging (4104) containing "New-Object Drawing.Bitmap" and "CopyFromScreen" API references
4. Sysmon file creation events (11) for .png files in temporary directories following PowerShell graphics API usage
5. Process access events (Sysmon 10) with full access rights (0x1FFFFF) from PowerShell to child processes during screen capture operations
6. .NET framework DLL loading patterns (Sysmon 7) including mscoree.dll and System.Management.Automation assemblies in PowerShell processes executing graphics operations
7. PowerShell module logging (4103) showing New-Object cmdlet usage with Drawing.Bitmap type and specific screen dimension arguments
