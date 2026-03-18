# T1115-1: Clipboard Data — Utilize Clipboard to store or execute commands from

## Technique Context

T1115 (Clipboard Data) is a Collection technique where adversaries access data stored on the system clipboard to gather information collected from users copying information within or between applications. This technique allows attackers to capture sensitive data like passwords, credentials, URLs, or other information that users have copied. Attackers may continuously monitor clipboard contents or capture clipboard data at specific intervals. The clipboard is accessible through Windows APIs like GetClipboardData() or command-line utilities like clip.exe.

Detection engineering typically focuses on monitoring clipboard access patterns, unusual processes accessing clipboard APIs, and command-line usage of clipboard utilities. The technique is often combined with keylogging or screen capture for comprehensive credential harvesting campaigns.

## What This Dataset Contains

This dataset captures the execution of a command that demonstrates both storing data to and retrieving data from the Windows clipboard using clip.exe. The Security channel shows the core process execution chain:

- A PowerShell process (PID 20328) spawning cmd.exe with the command: `"cmd.exe" /c dir | clip & echo "T1115" > %temp%\T1115.txt & clip < %temp%\T1115.txt`
- Two clip.exe processes being created to handle clipboard operations (PIDs 19580 and 16056)
- File creation of C:\Windows\Temp\T1115.txt by the cmd.exe process

Sysmon provides additional process creation details, showing whoami.exe execution (EID 1, PID 11132) and cmd.exe processes (PIDs 13276 and 21832). The technique involves piping directory output to clip.exe, creating a temporary file with "T1115" content, and then loading that file content into the clipboard using clip.exe's input redirection feature.

The PowerShell channel contains only test framework boilerplate (Set-ExecutionPolicy Bypass commands and Set-StrictMode scriptblocks), not the actual clipboard manipulation commands.

## What This Dataset Does Not Contain

The dataset lacks several elements that would provide more comprehensive clipboard monitoring coverage. There are no Windows API calls captured showing direct clipboard access through GetClipboardData(), OpenClipboard(), or SetClipboardData() functions. Registry modifications related to clipboard format registration are not present. The dataset also doesn't contain any PowerShell clipboard cmdlets usage (Get-Clipboard/Set-Clipboard) since those weren't used in this test.

Network connections are minimal, showing only Windows Defender telemetry, so there's no evidence of clipboard data exfiltration. File system monitoring shows the temporary file creation but doesn't capture the actual clipboard contents or format metadata that would indicate what type of data was stored.

## Assessment

This dataset provides solid coverage for detecting command-line clipboard utility usage, which is the most common implementation of T1115 in real attacks. The Security 4688 events with full command-line logging capture the exact clip.exe usage patterns, while Sysmon EID 1 events provide additional process ancestry and hash information for verification.

The process execution telemetry is excellent for building detections around clip.exe usage, particularly when combined with file operations or piped commands. However, the dataset would be stronger with additional API monitoring to catch more sophisticated clipboard access methods that bypass command-line utilities.

## Detection Opportunities Present in This Data

1. **Clipboard Utility Process Creation** - Security EID 4688 and Sysmon EID 1 showing clip.exe execution with command-line arguments, particularly input/output redirection operations

2. **Command Chain Analysis** - Composite command execution patterns using clip.exe with pipes and file redirection (dir | clip, clip < file) in Security 4688 command lines

3. **Temporary File Creation with Clipboard Context** - Sysmon EID 11 showing file creation in temp directories when correlated with subsequent clip.exe execution accessing those files

4. **Process Ancestry Patterns** - PowerShell or cmd.exe spawning clip.exe processes, captured in both Security 4688 (Creator Process Name) and Sysmon EID 1 (ParentImage) fields

5. **Clipboard Utility Frequency Analysis** - Multiple clip.exe process creations within short time windows, indicating potential clipboard monitoring or data harvesting campaigns
