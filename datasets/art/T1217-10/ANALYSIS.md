# T1217-10: Browser Information Discovery — Extract Edge Browsing History

## Technique Context

T1217 Browser Information Discovery involves adversaries accessing web browser data to understand user behavior, identify potential targets, or gather intelligence about the environment. This technique is particularly valuable during post-exploitation phases, as browser histories reveal visited websites, credentials stored in browsers, and user interests that can inform lateral movement or social engineering attacks.

Attackers commonly target browser databases and files containing browsing history, saved passwords, cookies, and bookmarks. Microsoft Edge stores browsing history in SQLite databases within the user profile, making it accessible to any process with sufficient privileges. Detection engineers focus on monitoring file access to browser directories, command-line evidence of browser data extraction, and unusual PowerShell activity targeting browser paths.

## What This Dataset Contains

This dataset captures a PowerShell-based extraction of Microsoft Edge browsing history executed as NT AUTHORITY\SYSTEM. The core technique involves reading the Edge History file and using regex pattern matching to extract URLs.

Security event 4688 shows the PowerShell process creation with the full command line: `"powershell.exe" & {$URL_Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%%&=]*)*?'\n$History = Get-Content -Path \"$Env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History\" | Select-String -AllMatches $URL_Regex | ForEach-Object { $_.Matches.Value } | Sort -Unique\n$History | Out-File -FilePath \"$Env:USERPROFILE\Downloads\edgebrowsinghistory.txt\"}`

PowerShell event 4103 reveals the technique failed because the target file path doesn't exist: `NonTerminatingError(Get-Content): "Cannot find path 'C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Edge\User Data\Default\History' because it does not exist."` The script proceeded to create an output file at `C:\Windows\system32\config\systemprofile\Downloads\edgebrowsinghistory.txt` despite the failed input operation.

Sysmon captured the complete process chain, including the parent PowerShell process (PID 37812), a child whoami.exe execution (PID 19980), and the main browser history extraction PowerShell process (PID 18016). File creation event (EID 11) shows the output file being created: `TargetFilename: C:\Windows\System32\config\systemprofile\Downloads\edgebrowsinghistory.txt`.

## What This Dataset Does Not Contain

The dataset lacks evidence of successful browser data extraction because the target Edge History file doesn't exist on this system profile. Running as SYSTEM means the script targets the system profile path rather than a user profile where Edge data would typically reside. There are no file access events to actual browser databases, no evidence of SQLite database interaction, and no captured browsing history data.

The Sysmon configuration's include-mode filtering means we don't see every process creation, though the PowerShell processes were captured due to their presence in the suspicious process patterns. Network connections that might occur if the extracted data were exfiltrated are not present since the technique failed at the data collection stage.

## Assessment

This dataset provides excellent telemetry for detecting browser information discovery attempts, even when unsuccessful. The combination of command-line logging in Security events and PowerShell script block logging creates multiple detection opportunities. The presence of the complete PowerShell command line in Security 4688 events is particularly valuable, as it shows the exact technique being employed including the regex pattern for URL extraction.

The failure mode actually enhances the dataset's value for detection engineering, as it demonstrates how attackers might target browser data from unexpected execution contexts (SYSTEM vs. user profiles). The file creation of an empty output file provides additional forensic evidence of the attempt.

## Detection Opportunities Present in This Data

1. **PowerShell command line containing browser file paths** - Security 4688 events showing PowerShell execution with `Microsoft\Edge\User Data\Default\History` in the command line parameters

2. **Browser history file access attempts** - PowerShell script block logging (4104) and module logging (4103) capturing `Get-Content` operations targeting browser database files

3. **Regex patterns for URL extraction** - Script block events containing suspicious regex patterns like `(htt(p|s))://([\w-]+\.)+[\w-]+` designed to extract web URLs

4. **File creation in Downloads directories** - Sysmon EID 11 showing creation of files with names like `edgebrowsinghistory.txt` or similar browser data extraction indicators

5. **PowerShell cmdlet sequences for data extraction** - Event 4103 showing the progression `Get-Content | Select-String | ForEach-Object | Sort | Out-File` which is a common pattern for browser data extraction

6. **Process access to browser-related processes** - Sysmon EID 10 showing PowerShell processes accessing other processes that might be browser-related (though not present in this specific execution)

7. **Parent-child process relationships** - Sysmon EID 1 showing PowerShell spawning additional PowerShell processes with browser-related command lines, indicating potential browser data collection activities
