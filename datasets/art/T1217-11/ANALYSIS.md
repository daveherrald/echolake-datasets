# T1217-11: Browser Information Discovery — Extract chrome Browsing History

## Technique Context

T1217 Browser Information Discovery is a reconnaissance technique where adversaries collect information from web browsers to understand user behavior, identify sensitive accounts, or locate stored credentials. Chrome browsing history extraction is particularly valuable as it reveals websites visited, search patterns, and potentially sensitive services accessed by users. Attackers commonly target browser artifacts during post-exploitation to identify high-value targets, understand organizational infrastructure, or locate cloud services and admin portals.

The detection community focuses on monitoring access to browser data files, PowerShell commands that parse browser databases, and file operations that create copies of browser artifacts. This technique often appears in credential harvesting campaigns and lateral movement phases.

## What This Dataset Contains

This dataset captures a PowerShell-based Chrome history extraction attempt executed by the SYSTEM account. The core activity involves:

**Process Chain**: The attack spawns a child PowerShell process (PID 6244) from a parent PowerShell (PID 8580) with the full command line: `"powershell.exe" & {$Username = (whoami).Split('\')[1]; $URL_Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'; $History = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History" | Select-String -AllMatches $URL_Regex | ForEach-Object { $_.Matches.Value } | Sort -Unique; $History | Out-File -FilePath "$Env:USERPROFILE\Downloads\chromebrowsinghistory.txt"}`

**Key Events**:
- Security 4688 events showing PowerShell process creation with full command line
- Sysmon EID 1 events for both PowerShell instances and whoami.exe executions
- PowerShell EID 4103 events showing `Get-Content` command execution with error: `"Cannot find path 'C:\Users\system\AppData\Local\Google\Chrome\User Data\Default\History' because it does not exist"`
- PowerShell EID 4104 script block logging capturing the complete attack script
- Sysmon EID 11 file creation showing `C:\Windows\System32\config\systemprofile\Downloads\chromebrowsinghistory.txt` being created
- Sysmon EID 10 process access events showing PowerShell accessing whoami.exe processes

**Technical Details**: The script attempts to read the Chrome History file, extract URLs using regex pattern matching, and output results to a text file. The technique fails because Chrome is not installed on this test system.

## What This Dataset Does Not Contain

The dataset is missing successful browser history extraction since Chrome is not installed on the test system. The PowerShell EID 4103 events show the error "Cannot find path 'C:\Users\system\AppData\Local\Google\Chrome\User Data\Default\History' because it does not exist." This means we don't see:
- Successful SQLite database access patterns
- Actual URL data being processed
- Network indicators from extracted browsing history
- Chrome process interactions or database locking behavior

Sysmon ProcessCreate events for the initial PowerShell processes are missing due to the sysmon-modular include-mode filtering, though Security 4688 events provide complete command line coverage. No registry modifications or Chrome profile enumeration activities are captured since the browser isn't present.

## Assessment

This dataset provides excellent telemetry for detecting browser information discovery attempts, particularly PowerShell-based approaches. The combination of Security 4688 command line logging, PowerShell script block logging (EID 4104), and command invocation logging (EID 4103) creates multiple detection layers. Even though the technique fails due to Chrome's absence, the attempt generates rich behavioral indicators.

The PowerShell logging is particularly valuable, capturing both the complete attack script and the detailed error message that reveals the technique's intent. Sysmon file creation events show the output file being created despite the failed history extraction, indicating the script's completion path.

For real-world detection engineering, this dataset demonstrates how defensive telemetry can capture attack attempts regardless of success, providing early warning capabilities for browser targeting activities.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Detection**: Monitor EID 4104 for scripts containing Chrome browser file paths like `\AppData\Local\Google\Chrome\User Data\Default\History` and URL regex patterns
2. **Command Line Analysis**: Detect Security 4688 events with PowerShell command lines referencing browser history file paths and regex patterns for URL extraction
3. **PowerShell Command Invocation Monitoring**: Track EID 4103 events showing `Get-Content` attempts against browser database files
4. **Suspicious File Creation**: Monitor Sysmon EID 11 for files created with names like "chromebrowsinghistory.txt" or similar browser artifact dumps
5. **Browser Path Access Attempts**: Detect file access errors in PowerShell logs mentioning browser profile directories, indicating reconnaissance attempts
6. **Process Chain Analysis**: Identify PowerShell child processes spawned with browser-related command line arguments, especially when combined with whoami execution
7. **URL Regex Pattern Detection**: Monitor PowerShell script content for HTTP/HTTPS URL extraction regex patterns commonly used in browser history parsing
