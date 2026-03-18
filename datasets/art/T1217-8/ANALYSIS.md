# T1217-8: Browser Information Discovery — List Internet Explorer Bookmarks using the command prompt

## Technique Context

T1217 (Browser Information Discovery) represents attackers' attempts to enumerate stored browser data including bookmarks, browsing history, saved passwords, and other artifacts that reveal user behavior and potential targets. This technique is particularly valuable during the discovery phase as browser data often contains credentials, internal URLs, and insights into organizational infrastructure. The community focuses heavily on detecting filesystem access to browser data stores, command-line enumeration of browser directories, and process creation patterns targeting browser artifacts.

This specific test simulates an attacker using command-line tools to discover Internet Explorer bookmarks stored in the user's Favorites directory. While IE usage has declined, many organizations still maintain IE bookmarks that can reveal internal resources and user habits.

## What This Dataset Contains

The dataset captures a PowerShell-based execution that spawns cmd.exe to enumerate Internet Explorer bookmarks. Key telemetry includes:

**Process Creation Chain:**
- Sysmon EID 1: `whoami.exe` execution with command line `"C:\Windows\system32\whoami.exe"` (PID 24640)
- Sysmon EID 1: `cmd.exe` execution with command line `"cmd.exe" /c dir /s /b %%USERPROFILE%%\Favorites` (PID 27932)
- Security EID 4688: Complementary process creation events showing the same command executions

**Browser Discovery Activity:**
- The cmd.exe process specifically targets `%USERPROFILE%\Favorites` with recursive directory listing (`dir /s /b`)
- Security EID 4688 shows the actual executed command as `"cmd.exe" /c dir /s /b %USERPROFILE%\Favorites`

**PowerShell Context:**
- Multiple PowerShell EID 4103/4104 events showing Set-ExecutionPolicy bypass operations
- Sysmon EID 17 events capturing PowerShell named pipes
- Process access events (Sysmon EID 10) showing PowerShell accessing spawned processes

**System-Level Artifacts:**
- Security EID 4703 showing token privilege adjustments for the PowerShell process
- File creation events (Sysmon EID 11) for PowerShell startup profiles
- Image load events (Sysmon EID 7) showing .NET runtime and Windows Defender components

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide complete visibility into browser discovery activities:

**Missing File Access Events:** No Sysmon EID 11 events showing actual access to bookmark files or favicon.ico files within the Favorites directory, likely due to sysmon-modular filtering rules not capturing generic file access patterns.

**No Registry Enumeration:** The test doesn't capture registry-based IE bookmark discovery (HKCU\Software\Microsoft\Internet Explorer\Main), which is another common browser discovery vector.

**Limited Process Details:** The sysmon-modular config's include-mode filtering means we only see cmd.exe and whoami.exe process creation because they match known suspicious patterns - other potential browser-related processes might be filtered out.

**No Network Artifacts:** No DNS queries or network connections related to discovered bookmark URLs, as this test only enumerates without accessing discovered resources.

## Assessment

This dataset provides solid telemetry for detecting command-line browser discovery techniques. The Security 4688 events with full command-line logging offer the strongest detection opportunities, clearly showing the browser directory enumeration pattern. The Sysmon process creation events complement this with additional context like process GUIDs and parent-child relationships.

The combination of PowerShell execution context and cmd.exe spawning with browser-specific directory targeting creates a detectable pattern. However, the dataset would be stronger with file access telemetry showing actual bookmark file reads and registry access patterns for comprehensive browser discovery coverage.

## Detection Opportunities Present in This Data

1. **Command-Line Browser Discovery Pattern** - Security EID 4688 and Sysmon EID 1 showing cmd.exe with arguments `dir /s /b` targeting `%USERPROFILE%\Favorites` or similar browser directories

2. **PowerShell-to-CMD Browser Enumeration** - Process creation chain from powershell.exe spawning cmd.exe with browser directory enumeration commands

3. **Recursive Directory Listing of Browser Paths** - Command-line patterns using `dir /s` or `dir /b` specifically targeting known browser data directories (Favorites, Bookmarks, etc.)

4. **Whoami Execution in Browser Discovery Context** - Sysmon EID 1 showing whoami.exe execution immediately before browser discovery commands, indicating reconnaissance activity

5. **PowerShell Process Access to Discovery Tools** - Sysmon EID 10 showing PowerShell accessing spawned reconnaissance tools with high-privilege access (0x1FFFFF)

6. **Browser Discovery Tool Execution** - Process creation of common discovery utilities (cmd.exe, dir commands) with browser-specific path arguments in the command line
