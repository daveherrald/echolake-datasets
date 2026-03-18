# T1027-10: Obfuscated Files or Information — Execution from Compressed JScript File

## Technique Context

T1027.010 (Obfuscated Files or Information: Command Obfuscation) represents attackers' use of compressed archives to deliver and execute malicious scripts while evading detection. This sub-technique focuses specifically on packaging scripts (particularly JScript/JavaScript) within compressed files like ZIP archives to bypass file-based security controls and obfuscate the true payload until execution.

Attackers commonly use this technique to:
- Evade static analysis by security tools that may not inspect compressed archive contents
- Bypass email security gateways that filter executable file types but allow archives
- Complicate incident response by requiring additional steps to extract and analyze payloads
- Leverage legitimate compression utilities and script execution engines to appear benign

Detection engineers typically focus on monitoring for script execution from temporary extraction paths, unusual command-line patterns involving archive extraction, and the execution of scripts with suspicious file paths or naming conventions.

## What This Dataset Contains

This dataset captures the execution of a JScript file from within a compressed archive. The key execution chain visible in the telemetry shows:

**Process Creation Chain (Security 4688):**
- PowerShell spawns `cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\temp_T1027js.zip\T1027js.js"`
- The command line reveals the technique attempting to execute a `.js` file directly from what appears to be a ZIP archive path

**Sysmon Process Creation (EID 1):**
- `whoami.exe` execution from PowerShell (ProcessGuid: {9dc7570a-48e1-69b4-d81c-000000001000}, PID 6240)
- `cmd.exe` execution with the suspicious command line (ProcessGuid: {9dc7570a-48e1-69b4-d91c-000000001000}, PID 5316)

**Process Access Events (Sysmon EID 10):**
- PowerShell accessing both `whoami.exe` and `cmd.exe` processes with full access rights (0x1FFFFF)
- Call traces showing System.Management.Automation involvement in process access

**Process Exit Behavior (Security 4689):**
- The `cmd.exe` process exits with status `0x1`, indicating failure
- This suggests the JScript execution attempt was unsuccessful

## What This Dataset Does Not Contain

The dataset lacks several critical elements that would typically accompany successful compressed script execution:

**Missing Script Host Activity:** No `wscript.exe`, `cscript.exe`, or Windows Script Host processes appear in the telemetry, which would normally handle `.js` file execution.

**No Archive Extraction Evidence:** There are no file creation events (Sysmon EID 11) showing the extraction of the JavaScript file from the ZIP archive to a temporary location.

**Limited PowerShell Script Content:** The PowerShell channel contains only test framework boilerplate (`Set-StrictMode`, `Set-ExecutionPolicy Bypass`) without the actual script content that would have performed the archive extraction and script execution.

**Missing Network Activity:** No DNS queries, network connections, or other network-related telemetry that might result from successful script execution.

The `cmd.exe` exit status of `0x1` and the absence of subsequent script host processes suggests that Windows was unable to directly execute the JavaScript file from within the ZIP archive path, which aligns with expected Windows behavior.

## Assessment

This dataset provides moderate value for detection engineering, primarily as an example of a failed technique execution. The telemetry effectively demonstrates the command-line patterns and process relationships that occur when attackers attempt this technique, even when unsuccessful.

The Security 4688 events with command-line logging provide excellent visibility into the attempted execution pattern, while Sysmon EID 1 events offer additional process creation context with file hashes and parent-child relationships. The process access events (EID 10) could be valuable for detecting PowerShell-initiated process manipulation, though they may generate false positives in legitimate automation scenarios.

The dataset would be significantly stronger if it included successful technique execution with corresponding script host processes, file extraction events, and potential post-execution activities. However, it serves as a useful baseline for understanding the initial execution attempt patterns.

## Detection Opportunities Present in This Data

1. **Suspicious Archive Path Execution** - Monitor Security 4688 and Sysmon EID 1 for command lines containing file paths with archive extensions (`.zip`, `.rar`, `.7z`) followed by script file extensions (`.js`, `.vbs`, `.ps1`)

2. **Script File Extension in Archive Paths** - Alert on command-line arguments containing patterns like `*.zip\*.js` or similar combinations of archive and script file extensions

3. **PowerShell-Spawned CMD with Archive Execution** - Detect PowerShell processes spawning `cmd.exe` with `/c` parameter and command lines referencing archive file paths

4. **Failed Script Execution Attempts** - Monitor for `cmd.exe` processes exiting with non-zero status codes when command lines reference script files within archive paths

5. **Process Access from PowerShell to Script Contexts** - Alert on PowerShell processes accessing `cmd.exe` or script host processes with high privilege access (0x1FFFFF) when associated command lines involve archive file paths

6. **Temporary Directory Script Execution** - Watch for script file execution from paths containing "temp", "atomics", or other temporary directory indicators, especially when parent processes involve archive handling
