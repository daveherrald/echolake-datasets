# T1218.007-8: Msiexec — WMI Win32_Product Class - Execute Local MSI file with an embedded EXE

## Technique Context

T1218.007 (Msiexec) is a defense evasion technique where attackers abuse the legitimate Windows Installer service (msiexec.exe) to proxy execution of malicious code. This technique is particularly valuable because msiexec.exe is a signed Microsoft binary that administrators and security tools generally trust. The Win32_Product WMI class provides programmatic access to software installation functionality, allowing attackers to remotely install MSI packages that contain embedded executables.

Attackers commonly use this technique to bypass application whitelisting, deploy backdoors, or execute payloads in enterprise environments where direct executable execution is restricted. The WMI Win32_Product approach is especially attractive because it can be invoked remotely and appears as legitimate software installation activity. Detection engineering focuses on unusual msiexec.exe executions, especially those initiated via WMI or PowerShell, and MSI installations from non-standard locations.

## What This Dataset Contains

This dataset captures a complete WMI-based MSI installation chain executed via PowerShell's `Invoke-CimMethod`. The attack chain shows:

**Initial PowerShell execution** (Security 4688, Sysmon EID 1): PowerShell process with command line `"powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_EXE.msi' }}`

**PowerShell script block logging** (PowerShell 4104): The exact CIM method invocation is logged: `Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_EXE.msi' }`

**MSI installation via msiexec** (Sysmon EID 11): File creation of `C:\Windows\Installer\327edf9.msi` and `C:\Windows\Installer\MSIAEF1.tmp` by msiexec.exe (PID 24948)

**Embedded executable execution** (Security 4688): The MSI package extracts and executes `C:\Windows\Installer\MSIAEF1.tmp` with command line `"C:\Windows\Installer\MSIAEF1.tmp" "Hello, Atomic Red Team from an EXE!"`

**Application event logging** (Application 1040, 1033, 11707): Complete Windows Installer transaction logs showing successful installation of "Atomic Red Team Test Installer" version 1.0.0

**Privilege adjustments** (Security 4703): Multiple token right adjustments for msiexec.exe, including SeRestorePrivilege and SeTakeOwnershipPrivilege enabling/disabling

The Sysmon data shows extensive .NET runtime loading across multiple PowerShell processes and the embedded executable, indicating the payloads leverage .NET assemblies.

## What This Dataset Does Not Contain

**Missing msiexec.exe process creation**: The initial msiexec.exe spawn is not captured in Sysmon EID 1 events, likely because the sysmon-modular configuration's include-mode filtering doesn't consider msiexec.exe suspicious by default.

**Limited network telemetry**: No DNS queries or network connections are present, indicating this test uses a local MSI file rather than demonstrating remote download scenarios.

**No registry modifications**: Despite MSI installations typically creating extensive registry changes for software registration, no registry events are captured, suggesting Sysmon registry monitoring is disabled.

**Missing file hash verification**: While Sysmon captures file creation events, the actual MSI and embedded executable hashes aren't provided for the created files, only for loaded system libraries.

**No WMI operation details**: The underlying WMI operations that bridge between PowerShell's Invoke-CimMethod and msiexec.exe execution aren't directly visible in the telemetry.

## Assessment

This dataset provides excellent coverage of the complete T1218.007 attack chain when executed via WMI Win32_Product class. The combination of Security 4688 command-line logging, PowerShell script block logging, and Sysmon file creation events gives detection engineers multiple high-fidelity detection opportunities. The Application event logs add valuable context about the actual software installation process.

The dataset is particularly strong for demonstrating how legitimate Windows functionality can be abused while generating defensive telemetry. The privilege adjustment events (Security 4703) provide additional forensic context about the elevated permissions msiexec.exe requires during installation. However, the missing msiexec.exe process creation event highlights the importance of comprehensive process monitoring beyond LOLBin-focused Sysmon configurations.

## Detection Opportunities Present in This Data

1. **PowerShell WMI Win32_Product usage**: Detect `Invoke-CimMethod -ClassName Win32_Product -MethodName Install` in PowerShell script blocks (EID 4104) or command lines (Security 4688)

2. **MSI installation from non-standard paths**: Alert on msiexec.exe installing packages from temporary directories, user profiles, or script directories rather than typical software distribution paths

3. **Rapid MSI extract-and-execute pattern**: Correlate msiexec.exe file creation in Windows\Installer with immediate executable launch from the same directory

4. **Embedded executable execution**: Monitor for process creation of .tmp files from Windows\Installer directory, especially with non-standard command-line arguments

5. **PowerShell to msiexec process relationship**: Build detections linking PowerShell CIM method calls to subsequent msiexec.exe activity within short time windows

6. **Application log correlation**: Use Windows Installer success logs (Application 1033) to identify potentially malicious software installations, especially from unknown publishers

7. **Token privilege escalation during installation**: Alert on SeRestorePrivilege and SeTakeOwnershipPrivilege adjustments by msiexec.exe, particularly when initiated by scripting engines

8. **MSI installation without user interaction**: Detect automated MSI installations (no GUI processes) initiated by PowerShell or other scripting engines rather than interactive user sessions
