# T1218-3: System Binary Proxy Execution — InfDefaultInstall.exe .inf Execution

## Technique Context

T1218 System Binary Proxy Execution encompasses techniques where adversaries leverage legitimate, signed Windows binaries to execute malicious code, bypassing application control mechanisms and potentially evading detection. The InfDefaultInstall.exe variant (T1218.022) specifically abuses Windows' INF file installation utility to execute arbitrary code embedded within specially crafted INF files.

InfDefaultInstall.exe is a legitimate Windows utility used to install device drivers and software components from INF files. Attackers exploit this by creating malicious INF files containing executable commands in their [DefaultInstall] section. When processed by InfDefaultInstall.exe, these commands execute with the same privileges as the calling process. This technique is particularly attractive because it uses a Microsoft-signed binary, potentially bypassing application whitelisting, and the INF file format can obfuscate malicious intent.

Detection engineers typically focus on monitoring InfDefaultInstall.exe executions, unusual INF file locations, and the command-line patterns that indicate non-standard usage. The technique often generates distinctive process chains and file access patterns that provide detection opportunities.

## What This Dataset Contains

This dataset captures a successful execution of T1218.003 with clear telemetry across multiple data sources. The attack chain begins with PowerShell and proceeds through the following process hierarchy:

**Process Chain:** `powershell.exe` → `cmd.exe` → `InfDefaultInstall.exe "C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf"`

**Key Security Event Log (4688) Evidence:**
- Process creation for `cmd.exe` with command line: `"cmd.exe" /c InfDefaultInstall.exe "C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf"`
- Process creation for `InfDefaultInstall.exe` with command line: `InfDefaultInstall.exe "C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf"`
- All processes executed under SYSTEM context with exit status 0x0 (success)

**Sysmon Evidence:**
- EID 1 (Process Create) for cmd.exe with RuleName matching T1059.003 (Windows Command Shell)
- EID 1 (Process Create) for InfDefaultInstall.exe with RuleName matching T1218 (System Binary Proxy Execution)
- Process GUID tracking shows clear parent-child relationships through the execution chain
- InfDefaultInstall.exe hash: SHA256=D6A03550FBD2313A8B1F4E71180BF27DB436A86BD54660E4A6C6B6707BDF8D63

The dataset also includes a `whoami.exe` execution that appears to be part of the test setup, demonstrating system enumeration capabilities.

## What This Dataset Does Not Contain

The dataset does not show the actual contents or effects of the malicious INF file execution. While we can observe InfDefaultInstall.exe being launched successfully, we don't see:

- Registry modifications that may have been performed by the INF file
- Additional file operations beyond basic PowerShell startup files
- Network connections that might result from payload execution
- The specific commands embedded within the INF file's [DefaultInstall] section

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass) rather than the actual test execution commands. This is typical for Atomic Red Team test executions where the PowerShell wrapper invokes external processes.

Windows Defender was active during execution but did not block this technique, as evidenced by the successful process creation and zero exit codes. This demonstrates that basic INF file abuse via InfDefaultInstall.exe may not trigger immediate EDR response, making behavioral detection crucial.

## Assessment

This dataset provides excellent telemetry for detecting T1218.003 through multiple complementary data sources. The Security event logs (4688) offer complete process creation visibility with full command lines, while Sysmon adds process GUIDs for correlation and rule-based alerting. The combination enables both signature-based detection on the InfDefaultInstall.exe execution pattern and behavioral analysis of the unusual process chain.

The dataset's strength lies in showing the complete attack chain from initial PowerShell execution through final binary proxy execution. The presence of both cmd.exe and InfDefaultInstall.exe in the chain provides multiple detection points. However, the dataset would be stronger if it included the downstream effects of the INF file processing, such as registry changes or additional process creation events.

For detection engineering, this data demonstrates that InfDefaultInstall.exe abuse generates clear, actionable telemetry that should be readily detectable with properly configured process monitoring.

## Detection Opportunities Present in This Data

1. **InfDefaultInstall.exe Process Execution** - Monitor for any execution of InfDefaultInstall.exe (Image path C:\Windows\System32\InfDefaultInstall.exe) as it's rarely used in legitimate enterprise environments

2. **Command Line Pattern Analysis** - Alert on InfDefaultInstall.exe command lines referencing non-standard INF file locations, particularly user-writable directories or paths outside Windows system directories

3. **Process Chain Analysis** - Detect cmd.exe spawning InfDefaultInstall.exe, especially when the parent process is PowerShell or other scripting engines

4. **Parent Process Anomalies** - InfDefaultInstall.exe should typically be launched by Windows Installer or setup processes, not by cmd.exe or PowerShell

5. **Sysmon Rule Correlation** - Leverage Sysmon's built-in T1218 rule matching to identify System Binary Proxy Execution attempts in real-time

6. **File Path Analysis** - Monitor for INF file access patterns in unusual locations (non-system directories, user profiles, temp directories) combined with InfDefaultInstall.exe execution

7. **Process GUID Correlation** - Use Sysmon Process GUIDs to track the complete execution chain and identify related malicious activity across the attack sequence
