# T1115-2: Clipboard Data — Execute Commands from Clipboard using PowerShell

## Technique Context

T1115 (Clipboard Data) involves adversaries accessing clipboard contents to collect sensitive information like passwords, URLs, or commands that users have copied. This specific test demonstrates a more sophisticated variant where PowerShell is used not just to read clipboard data, but to execute commands retrieved from the clipboard using `Get-Clipboard | Invoke-Expression`. This technique could allow adversaries to execute arbitrary PowerShell commands by manipulating clipboard contents, either through social engineering or by exploiting applications that automatically populate the clipboard. Detection engineers focus on monitoring clipboard access APIs, PowerShell execution patterns, and the dangerous combination of clipboard reading with command execution functions like `Invoke-Expression` or `iex`.

## What This Dataset Contains

This dataset captures a complete execution of clipboard-based command execution in PowerShell. The test uses the command `& {echo Get-Process | clip; Get-Clipboard | iex}` which first places "Get-Process" into the clipboard using `clip.exe`, then retrieves and executes it via `Get-Clipboard | iex`.

Security event 4688 shows the process creation chain: the parent PowerShell process (PID 24216) spawns a child PowerShell process (PID 36600) with the full command line `"powershell.exe" & {echo Get-Process | clip; Get-Clipboard | iex}`. The child process then creates `clip.exe` (PID 41392) with command line `"C:\Windows\system32\clip.exe"`.

PowerShell script block logging (EID 4104) captures the malicious scriptblock `& {echo Get-Process | clip; Get-Clipboard | iex}` and shows the individual command executions. PowerShell module logging (EID 4103) reveals the specific cmdlet invocations: `Write-Output` with parameter "Get-Process", `clip.exe` execution, `Get-Clipboard`, and critically, `Invoke-Expression` with parameter "Get-Process". The logs also show a binding error: "Cannot bind argument to parameter 'Command' because it is an empty string" suggesting some timing issues with clipboard access.

Sysmon captures process creation events for both the child PowerShell process and `clip.exe` with their full command lines. Sysmon EID 10 (Process Access) events show PowerShell accessing both `whoami.exe` and `clip.exe` processes, indicating the test also ran a system discovery command.

## What This Dataset Does Not Contain

The dataset doesn't capture the actual clipboard contents or clipboard API calls directly, as these require specialized monitoring beyond standard Windows logging. There are no network connections since this test operates entirely locally. The dataset also doesn't show any file-based persistence mechanisms or credential harvesting, as this test focuses purely on the command execution aspect of clipboard abuse. Notably missing are any Windows Defender alerts or blocks, suggesting this technique executed successfully without triggering real-time protection.

## Assessment

This dataset provides excellent visibility into clipboard-based command execution through multiple complementary data sources. The combination of Security 4688 with full command-line logging, PowerShell script block logging, and Sysmon process creation events creates a comprehensive detection foundation. The PowerShell logs are particularly valuable, capturing both the script blocks and the specific cmdlet invocations that make this technique dangerous. The presence of `Invoke-Expression` combined with `Get-Clipboard` in the same execution context is a strong behavioral indicator. While the dataset doesn't capture low-level clipboard API calls, the process-level and PowerShell-level telemetry provides sufficient detection opportunities for this technique.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis** - Monitor EID 4104 for script blocks containing both `Get-Clipboard` and `Invoke-Expression` (or `iex`) in the same context, indicating potential clipboard-based code execution.

2. **PowerShell Module Logging Correlation** - Detect EID 4103 showing sequential execution of `Get-Clipboard` followed by `Invoke-Expression` within the same PowerShell session, especially when the `Invoke-Expression` parameter matches clipboard content.

3. **Process Chain Analysis** - Monitor for PowerShell processes spawning `clip.exe` followed by immediate PowerShell cmdlet execution, creating a behavioral pattern of clipboard manipulation and command execution.

4. **Command Line Pattern Matching** - Alert on Security 4688 events showing PowerShell command lines containing the pattern `Get-Clipboard | iex` or similar clipboard-to-execution pipelines.

5. **Suspicious PowerShell Parameter Binding** - Monitor PowerShell logs for `Invoke-Expression` cmdlet invocations where the Command parameter is dynamically populated, particularly from clipboard sources.

6. **Cross-Process Clipboard Access** - Use Sysmon EID 10 to detect PowerShell processes accessing clipboard-related processes or making unusual process access calls during clipboard operations.
