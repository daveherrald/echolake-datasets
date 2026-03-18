# T1137.006-3: Add-ins — Persistent Code Execution Via Word Add-in File (WLL)

## Technique Context

T1137.006 focuses on Office application add-ins as a persistence mechanism. Attackers leverage add-ins to maintain persistence by automatically loading malicious code when Office applications start. Word Library (WLL) files are dynamic-link libraries that extend Microsoft Word functionality and load automatically when Word starts if placed in specific directories like the Word Startup folder (`%APPDATA%\Microsoft\Word\Startup\`). This technique is particularly valuable for persistence because it survives reboots and executes in the context of a trusted application. Detection communities focus on monitoring file creation in Office startup directories, COM object instantiation for Office applications, and unusual DLL loads from Office processes.

## What This Dataset Contains

This dataset captures a failed attempt to establish Word add-in persistence. The PowerShell script attempts to determine Office architecture by instantiating a Word.Application COM object, then copy the appropriate WLL file to the Word Startup directory. However, the technique fails because Word/Office is not installed on the test system.

Key evidence includes:
- Security 4688 showing PowerShell execution with the full command line: `"powershell.exe" & {$wdApp = New-Object -COMObject \"Word.Application\"...Copy \"C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\wordwll_x64.wll\" \"$env:APPDATA\Microsoft\Word\Startup\notepad.wll\"...}`
- PowerShell 4104 script block logging capturing the complete attack script including COM object instantiation and file copy operations
- PowerShell 4100 error showing COM class factory failure: `Retrieving the COM class factory for component with CLSID {00000000-0000-0000-0000-000000000000} failed due to the following error: 80040154 Class not registered`
- PowerShell 4100 error showing failed Word process start: `This command cannot be run due to the error: The system cannot find the file specified` for the `Start-Process "WinWord"` command
- Sysmon 1 events for whoami.exe execution and the spawned PowerShell child process
- No Sysmon 11 events showing successful file creation in the Word Startup directory

## What This Dataset Does Not Contain

The dataset lacks evidence of successful technique execution because Word/Office is not installed. Missing elements include:
- Successful COM object instantiation for Word.Application
- File creation events (Sysmon 11) for the WLL file being copied to `%APPDATA%\Microsoft\Word\Startup\`
- Word process creation (WinWord.exe) and associated DLL loading events
- Registry modifications that might occur during Office add-in registration
- Network connections or other post-exploitation activities that would occur after successful WLL loading

The Sysmon ProcessCreate filtering explains why we don't see certain process creations, but the primary limitation here is the absence of the target application.

## Assessment

This dataset provides limited value for detection engineering because it only captures the failed attempt rather than successful execution. The telemetry is valuable for understanding attack patterns and failure modes, but doesn't demonstrate the complete attack lifecycle. The PowerShell script block logging and command-line auditing provide excellent visibility into the attacker's intentions and methodology. For complete detection development, this would need to be paired with successful execution data from a system with Office installed.

The Security 4688 events with full command-line logging and PowerShell script block logging provide the strongest detection opportunities, even in failure scenarios.

## Detection Opportunities Present in This Data

1. **Office COM Object Instantiation**: PowerShell 4104 script blocks showing `New-Object -COMObject "Word.Application"` attempts, which may indicate reconnaissance or preparation for Office-based attacks.

2. **Word Startup Directory File Operations**: Command-line references to copying files to `$env:APPDATA\Microsoft\Word\Startup\` paths, detectable in Security 4688 command-line logging.

3. **WLL File Manipulation**: References to `.wll` files in PowerShell commands and potential file operations targeting Word Library files.

4. **Office Process Control**: PowerShell commands attempting to stop and start Word processes (`Stop-Process -Name "WinWord"` and `Start-Process "WinWord"`).

5. **Office Architecture Detection**: PowerShell scripts checking Office installation paths for architecture determination, which may indicate targeting preparation.

6. **Atomic Red Team Artifact Paths**: File paths referencing `C:\AtomicRedTeam\atomics\T1137.006\bin\Addins\` indicating test execution or similar tooling usage.

7. **PowerShell Error Patterns**: COM registration errors (0x80040154) combined with Office-related operations that may indicate failed persistence attempts on systems without Office.
