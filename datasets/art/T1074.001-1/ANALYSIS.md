# T1074.001-1: Local Data Staging — Stage data from Discovery.bat

## Technique Context

T1074.001 Local Data Staging involves adversaries collecting data from multiple sources and organizing it into a central location before exfiltration. This technique is a critical preparatory step in the data theft process, allowing attackers to efficiently package information for removal from the target environment. The detection community focuses on identifying unusual file operations in temporary directories, the creation of compressed archives, and scripts that systematically gather files from various locations. This particular Atomic Red Team test simulates the staging preparation by downloading a discovery batch file that would typically be used to identify and collect data of interest.

## What This Dataset Contains

This dataset captures the preparation phase of data staging through PowerShell downloading a reconnaissance script. The primary activity visible is:

**PowerShell Web Request Activity**: Security event 4688 shows the initial PowerShell process creation with command line `"powershell.exe" & {Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.bat" -OutFile $env:TEMP\discovery.bat}`. PowerShell event 4103 confirms the Invoke-WebRequest execution with parameters targeting the GitHub URL and output to `C:\Windows\TEMP\discovery.bat`.

**File Creation**: Sysmon event 11 documents the actual file creation at `C:\Windows\Temp\discovery.bat` by the PowerShell process (PID 27736), confirming successful download of the staging script.

**Process Chain**: The execution shows PowerShell spawning `whoami.exe` (captured in Sysmon event 1 with command line `"C:\Windows\system32\whoami.exe"`), indicating some initial system reconnaissance occurred during the test.

**Network Activity Evidence**: While network connections aren't directly visible, the successful file download and loading of `urlmon.dll` (Sysmon event 7) indicates the web request completed successfully.

## What This Dataset Does Not Contain

This dataset captures only the preparation phase, not the actual data staging behavior. The Discovery.bat file that was downloaded is not executed, so there's no evidence of:

- File enumeration and collection activities
- Data aggregation into staging directories
- Archive creation or compression operations
- Large-scale file copying or moving operations
- The actual discovery commands that would identify sensitive data locations

The test also doesn't include any blocked activities from Windows Defender, suggesting the preparation phase completed without interference. DNS resolution events are absent, likely filtered by the Sysmon configuration.

## Assessment

This dataset provides limited but useful telemetry for detecting the initial preparation phase of data staging operations. The combination of PowerShell execution with web requests to download reconnaissance tools represents a common attacker pattern. However, the dataset's value is constrained by capturing only the setup phase rather than the full staging behavior. The Security 4688 events with full command-line logging provide the most valuable detection opportunities, while the Sysmon file creation events confirm successful tool deployment. For comprehensive data staging detection, additional datasets showing the actual execution of discovery scripts and subsequent file operations would be necessary.

## Detection Opportunities Present in This Data

1. **PowerShell downloading external scripts** - Security event 4688 with command lines containing `Invoke-WebRequest` to GitHub URLs hosting reconnaissance tools, particularly targeting the `/atomics/` path structure common in red team frameworks.

2. **Reconnaissance tool deployment to temp directories** - Sysmon event 11 showing `.bat` files created in `%TEMP%` locations by PowerShell processes, especially when accompanied by web request activity.

3. **PowerShell module invocation for web requests** - PowerShell event 4103 CommandInvocation logs showing `Invoke-WebRequest` cmdlet usage with external URLs as staging preparation behavior.

4. **Discovery tool execution patterns** - Sysmon event 1 process creation for `whoami.exe` spawned by PowerShell processes that previously performed web requests, indicating reconnaissance following tool acquisition.

5. **URL pattern matching** - Command-line arguments containing URLs with patterns like `raw.githubusercontent.com` and paths containing `/atomic` or similar red team framework indicators.

6. **Process access patterns** - Sysmon event 10 showing PowerShell processes accessing newly spawned reconnaissance tools like `whoami.exe` with high-privilege access rights (0x1FFFFF).
