# T1218.007-5: Msiexec — WMI Win32_Product Class - Execute Local MSI file with embedded JScript

## Technique Context

T1218.007 represents the abuse of msiexec.exe, the Windows Installer service executable, for defense evasion. This technique leverages the fact that msiexec.exe is a signed Microsoft binary that can execute code from MSI packages, making it an attractive LOLBin (Living Off The Land Binary) for attackers. The specific variant tested here uses WMI's Win32_Product class to install an MSI package containing embedded JScript, combining multiple attack vectors: WMI for execution, MSI for code delivery, and JScript for the payload.

Detection engineers focus on unusual msiexec.exe executions, particularly those initiated through WMI or PowerShell, MSI installations from non-standard locations, and the presence of embedded scripts in MSI packages. The Win32_Product.Install method is particularly suspicious as it's commonly used in automated attacks to programmatically install malicious MSI packages.

## What This Dataset Contains

This dataset captures a PowerShell-based execution of the technique using WMI's Win32_Product class. The key evidence includes:

**PowerShell Script Block (EID 4104)**: The core technique execution is captured in script block logging: `& {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi' }}`. This shows the exact WMI method call used to install the malicious MSI.

**Process Creation Evidence (Security EID 4688)**: Shows the PowerShell process created with command line `"powershell.exe" & {Invoke-CimMethod -ClassName Win32_Product -MethodName Install -Arguments @{ PackageLocation = 'C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi' }}`, providing the full execution context.

**Windows Installer Events (Application EID 1040/1042)**: Captures the MSI installation transaction beginning and ending for `C:\AtomicRedTeam\atomics\T1218.007\bin\T1218.007_JScript.msi` with Client Process Id 4520, confirming the Windows Installer service processed the package.

**Sysmon Process Access (EID 10)**: Shows PowerShell processes accessing other processes with full access rights (0x1FFFFF), indicating the CIM operations' system-level interactions during MSI execution.

## What This Dataset Does Not Contain

The dataset is missing several critical components that would make it more complete for detection engineering:

**No msiexec.exe Process Creation**: The Sysmon ProcessCreate events don't capture msiexec.exe execution, likely because it doesn't match the sysmon-modular include patterns. This is a significant gap since msiexec.exe is the actual execution vector.

**No JScript Execution Evidence**: While the MSI contains embedded JScript, there's no telemetry showing the script execution itself - no script engine loading, no script content in logs, and no artifacts from the JScript payload.

**Limited WMI Telemetry**: The dataset lacks detailed WMI operational logs that would show the Win32_Product class instantiation and method invocation details.

**No File System Evidence**: Missing are file creation events for temporary MSI extraction, registry modifications typically associated with MSI installations, or other persistence mechanisms the JScript might establish.

## Assessment

This dataset provides moderate utility for detection engineering, primarily valuable for detecting the PowerShell/WMI initiation vector rather than the complete msiexec.exe abuse chain. The PowerShell script block logging excellently captures the attack initiation, and the Windows Installer application logs confirm MSI processing occurred. However, the absence of msiexec.exe process telemetry significantly limits its usefulness for understanding the full technique execution.

The dataset is strongest for detecting PowerShell-based WMI abuse patterns but weaker for comprehensive msiexec.exe behavioral analysis. Detection engineers can build effective rules around the PowerShell patterns but would need additional data sources for complete coverage of this technique variant.

## Detection Opportunities Present in This Data

1. **PowerShell Win32_Product Install Method Usage**: Alert on PowerShell script blocks containing `Invoke-CimMethod -ClassName Win32_Product -MethodName Install` with suspicious package locations outside standard software directories.

2. **Suspicious MSI Installation Paths**: Monitor Application Event Log EID 1040/1042 for MSI installations from non-standard locations like user directories, temp folders, or unusual file paths containing technique identifiers.

3. **PowerShell Process Command Line Analysis**: Detect Security EID 4688 events where PowerShell command lines contain WMI Win32_Product class usage combined with local file paths ending in .msi.

4. **PowerShell CIM Module Loading with File References**: Alert on PowerShell script blocks that combine CIM cmdlets with local file system paths, particularly those referencing executables or installer packages.

5. **Rapid MSI Transaction Patterns**: Correlate Application EID 1040/1042 pairs with short duration times that might indicate automated or scripted MSI installations rather than legitimate user-initiated software installations.

6. **PowerShell Process Access Correlation**: Use Sysmon EID 10 events showing PowerShell processes accessing multiple other processes during timeframes correlating with Win32_Product WMI operations to identify potential abuse patterns.
