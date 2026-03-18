# T1217-6: Browser Information Discovery — Browser Information Discovery - List Google Chrome / Edge Chromium Bookmarks on Windows with command prompt

## Technique Context

T1217 (Browser Information Discovery) involves adversaries attempting to gather information about the victim's web browsing activity to understand commonly visited sites, social media accounts, stored credentials, and other valuable intelligence. This specific test focuses on discovering Chromium-based browser bookmark files using command-line utilities. Attackers commonly target bookmark files because they reveal user habits, frequently accessed resources, and can contain indicators of valuable accounts or services. The detection community focuses on file system searches for browser-specific artifacts, particularly when conducted via command-line tools that can indicate automated or scripted reconnaissance activities.

## What This Dataset Contains

This dataset captures a PowerShell-initiated search for browser bookmark files using the Windows `where` command. The key telemetry shows:

**Process Creation Chain (Security 4688 events):**
- Initial PowerShell process (`powershell.exe`) executed by NT AUTHORITY\SYSTEM
- Command execution: `"cmd.exe" /c where /R C:\Users\ Bookmarks`
- File search utility: `where /R C:\Users\ Bookmarks`

**Sysmon Process Events:**
- Sysmon EID 1 captures the same process creations with enhanced context
- `whoami.exe` execution (likely test framework verification): `"C:\Windows\system32\whoami.exe"`
- CMD shell spawning: `"cmd.exe" /c where /R C:\Users\ Bookmarks`
- Where utility execution: `where /R C:\Users\ Bookmarks`

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing both whoami.exe and cmd.exe processes with full access (0x1FFFFF)
- Access patterns consistent with process creation and management

**PowerShell Activity:**
- Standard test framework boilerplate only (Set-StrictMode, Set-ExecutionPolicy Bypass)
- No actual technique-specific PowerShell script block logging captured

**Exit Status Indicators:**
- The `where.exe` process exits with status 0x1, indicating no bookmark files were found in the search path

## What This Dataset Does Not Contain

The dataset lacks several elements that would be present in a real-world scenario:

**File Access Telemetry:** Sysmon file access events (EID 11) only show PowerShell profile creation, not actual bookmark file access attempts. This suggests either no bookmark files existed in the search path or the sysmon-modular configuration doesn't capture file reads for these specific paths.

**Network Activity:** No DNS queries or network connections that might occur if discovered bookmarks were processed or exfiltrated.

**Registry Activity:** No registry access events that might accompany browser artifact discovery, though this specific test focuses on file system search rather than registry enumeration.

**Successful Discovery:** The exit code 0x1 from where.exe indicates the search found no matching files, so this represents an unsuccessful discovery attempt rather than actual data access.

## Assessment

This dataset provides excellent telemetry for detecting command-line based browser artifact discovery attempts. The process creation events clearly show the technique execution pattern, and the command-line logging captures the specific search parameters. The combination of Security 4688 events with full command-line logging and Sysmon EID 1 events provides comprehensive coverage of the process execution chain. However, the dataset would be more valuable if it included successful discovery attempts that would generate file access telemetry and demonstrate the complete attack workflow.

## Detection Opportunities Present in This Data

1. **Command-line browser artifact search patterns** - Security 4688 and Sysmon EID 1 events showing `where.exe` or similar utilities searching for browser-specific files like "Bookmarks" in user directories

2. **Recursive directory search behavior** - Process creation events showing `/R` recursive search flags combined with browser artifact keywords in user profile paths

3. **PowerShell-spawned discovery tools** - Process lineage showing PowerShell executing command-line discovery utilities, particularly when targeting browser data locations

4. **Browser data location enumeration** - Command-line patterns targeting `C:\Users\` with browser-specific file names or extensions

5. **Process access patterns during discovery** - Sysmon EID 10 events showing PowerShell accessing file discovery processes with elevated privileges (0x1FFFFF access)

6. **Cross-tool discovery chains** - Sequences of different discovery utilities (where, dir, findstr) executed in succession targeting browser artifact locations
