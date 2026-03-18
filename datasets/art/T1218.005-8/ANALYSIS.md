# T1218.005-8: Mshta — Invoke HTML Application - JScript Engine with Inline Protocol Handler

## Technique Context

T1218.005 (Mshta) is a defense evasion technique where attackers abuse the Microsoft HTML Application Host (mshta.exe) to execute malicious code while bypassing application controls. Mshta.exe is a signed Microsoft binary that can execute HTML Applications (.hta files) containing embedded scripting languages like JScript or VBScript. Attackers leverage this legitimate Windows utility to proxy execution of malicious code, making detection more challenging since the execution appears to originate from a trusted system binary.

This specific test (T1218.005-8) demonstrates using mshta.exe with an inline protocol handler ("about:") combined with JScript execution. This technique allows attackers to execute JavaScript code directly through mshta.exe without requiring external files, making it particularly stealthy. Detection engineers typically focus on monitoring mshta.exe process creation with suspicious command lines, network connections, child process spawning, and unusual script execution patterns.

## What This Dataset Contains

This dataset captures the execution of an Atomic Red Team test that invokes mshta.exe through PowerShell using the `Invoke-ATHHTMLApplication` function. The key telemetry includes:

**PowerShell Script Block Logging (EID 4104)** shows the actual test execution: `"& {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -MSHTAFilePath $env:windir\system32\mshta.exe}"` and the wrapped command: `"{Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -MSHTAFilePath $env:windir\system32\mshta.exe}"`.

**Security audit events** capture the PowerShell process creation with the complete command line: `"powershell.exe" & {Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler About -MSHTAFilePath $env:windir\system32\mshta.exe}` (EID 4688). The events also show a `whoami.exe` child process execution, indicating the test completed some discovery activity.

**Sysmon telemetry** provides detailed process creation for both the PowerShell test framework and the `whoami.exe` child process (EID 1), along with process access events (EID 10) showing PowerShell accessing both spawned processes. Multiple .NET runtime DLL loads are captured (EID 7) as PowerShell initializes its execution environment.

**Process termination events** (Security EID 4689) show normal exit codes (0x0) for all processes, indicating successful completion rather than defensive blocking.

## What This Dataset Does Not Contain

Critically, this dataset **does not contain any mshta.exe process creation events**. Despite the test's intended purpose of demonstrating mshta.exe abuse, no Sysmon EID 1 or Security EID 4688 events show mshta.exe being spawned. The Sysmon configuration's include-mode filtering for ProcessCreate events may have excluded mshta.exe if it wasn't specifically listed as a monitored process, or Windows Defender may have prevented the mshta.exe execution entirely.

The dataset lacks network connection events from mshta.exe, file creation events typical of HTA execution, and any registry modifications that might occur during HTML Application processing. There are no failed process creation events or access denied errors that would indicate Defender intervention, making the absence of mshta.exe execution unclear.

The PowerShell script block logs contain primarily test framework boilerplate (`Set-StrictMode`, error handling functions) rather than detailed script execution content that would show the actual mshta.exe invocation mechanics.

## Assessment

This dataset has **limited utility** for T1218.005 detection engineering because it fails to capture the core technique execution. While it demonstrates how PowerShell can be used as a launching mechanism for mshta.exe-based attacks, the absence of actual mshta.exe process creation significantly reduces its value for understanding the technique's telemetry signature.

The dataset is more valuable for understanding PowerShell-based attack frameworks and child process spawning patterns than for mshta.exe abuse specifically. The process access events and .NET runtime loading patterns could be useful for detecting PowerShell-based attack toolkits, but this doesn't fulfill the primary objective of demonstrating mshta.exe defense evasion.

For comprehensive T1218.005 detection development, additional datasets showing successful mshta.exe execution with various command line patterns, network behaviors, and file system interactions would be necessary.

## Detection Opportunities Present in This Data

1. **PowerShell execution with mshta.exe references** - Monitor PowerShell script blocks containing "mshta.exe", "Invoke-ATHHTMLApplication", or "InlineProtocolHandler" keywords (EID 4104)

2. **Suspicious PowerShell command line patterns** - Detect PowerShell processes with command lines referencing mshta.exe paths and script engines (Security EID 4688, CommandLine field)

3. **PowerShell child process spawning** - Monitor PowerShell processes spawning discovery utilities like whoami.exe, especially when combined with mshta.exe-related activity (Sysmon EID 1, ParentImage analysis)

4. **Process access patterns from PowerShell** - Detect PowerShell processes accessing newly created child processes with full access rights (Sysmon EID 10, GrantedAccess: 0x1FFFFF)

5. **PowerShell execution environment loading** - Correlate System.Management.Automation.dll loading with suspicious command line execution for attack framework detection (Sysmon EID 7)

6. **Atomic Red Team function usage** - Monitor for specific PowerShell functions like "Invoke-ATHHTMLApplication" that indicate testing or attack framework usage (EID 4104)
