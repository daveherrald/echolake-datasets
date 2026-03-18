# T1217-7: Browser Information Discovery — List Mozilla Firefox bookmarks on Windows with command prompt

## Technique Context

T1217 (Browser Information Discovery) involves adversaries accessing stored browser data to gather intelligence about user browsing habits, saved credentials, bookmarks, and other sensitive information. This technique is particularly valuable during the discovery phase of an attack, as browser data can reveal organizational infrastructure, frequently accessed systems, and potential lateral movement targets. The detection community focuses on monitoring file system access to browser profile directories, especially for SQLite databases containing bookmarks (places.sqlite for Firefox), passwords, and browsing history. This specific test attempts to locate Firefox bookmark databases using the Windows `where` command, which is a common reconnaissance approach that doesn't require specialized browser forensics tools.

## What This Dataset Contains

The primary telemetry shows a PowerShell process (PID 30976) executing a command to search for Firefox bookmark files: `"cmd.exe" /c where /R C:\Users\ places.sqlite`. This generates a clear process chain visible in Security 4688 events and Sysmon EID 1 events:

- PowerShell spawns cmd.exe with command line: `"cmd.exe" /c where /R C:\Users\ places.sqlite`
- cmd.exe spawns where.exe with command line: `where /R C:\Users\ places.sqlite`
- The where.exe process exits with status 0x1, indicating no files were found (no Firefox profiles present on the test system)

The process access telemetry in Sysmon EID 10 shows PowerShell accessing both the cmd.exe and where.exe processes with full access rights (0x1FFFFF), which is normal parent-child process behavior. The dataset also captures typical PowerShell initialization events including .NET runtime loading and Windows Defender integration, but the PowerShell script block logging (EID 4104) contains only test framework boilerplate with Set-StrictMode calls rather than the actual browser discovery commands.

## What This Dataset Does Not Contain

This dataset lacks the actual Firefox bookmark data access that would occur if Firefox were installed and had user profiles. Since where.exe exits with code 0x1 (file not found), we don't see file access events to places.sqlite databases, which would be the primary indicator of successful browser information discovery. The PowerShell script block logging doesn't capture the command construction that led to the cmd/where execution, showing only framework boilerplate. Additionally, there are no file enumeration events showing directory traversal patterns that might indicate broader browser profile hunting beyond the specific where command executed.

## Assessment

This dataset provides excellent coverage for detecting the command-line reconnaissance phase of browser information discovery attempts. The Security 4688 and Sysmon EID 1 events clearly capture the diagnostic command patterns that are reliable indicators of this technique, regardless of whether target files exist. However, the dataset represents an unsuccessful discovery attempt due to the absence of Firefox on the test system, so it doesn't demonstrate the file access patterns that would occur during successful browser data harvesting. The telemetry quality is high for building detections around the reconnaissance phase but limited for understanding post-discovery file access behaviors.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security 4688 and Sysmon EID 1 events showing `where` commands with `/R` flag recursively searching user directories for browser-specific files like "places.sqlite", "Login Data", or "Cookies"

2. **Browser reconnaissance process chains** - Process creation sequences where PowerShell or cmd.exe spawn where.exe, dir, or forfiles commands targeting common browser profile locations under C:\Users\

3. **Recursive file search patterns** - Commands using `/R` parameter to recursively search directory trees, particularly when combined with browser artifact filenames

4. **Cross-browser discovery campaigns** - Multiple sequential searches for different browser databases (places.sqlite for Firefox, Login Data for Chrome, etc.) suggesting systematic browser reconnaissance

5. **PowerShell-initiated discovery** - PowerShell processes spawning native Windows utilities for file system reconnaissance, particularly targeting browser profile directories
