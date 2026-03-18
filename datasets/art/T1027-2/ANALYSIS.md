# T1027-2: Obfuscated Files or Information — Execute base64-encoded PowerShell

## Technique Context

T1027 (Obfuscated Files or Information) is a defense evasion technique where attackers disguise or hide malicious code to avoid detection by security tools. This specific test demonstrates a common PowerShell obfuscation pattern: encoding commands in base64 to bypass string-based detections and evade casual inspection.

The technique works by converting PowerShell commands to UTF-16LE bytes, then encoding them as base64, which can be executed using PowerShell's `-EncodedCommand` parameter. This is particularly popular with attackers because it allows complex commands to be passed through command-line interfaces that might otherwise have character restrictions or logging gaps.

The detection community focuses on identifying base64-encoded PowerShell execution, suspicious process chains involving multiple PowerShell instances, and the characteristic command-line patterns that emerge from this technique. This is considered a high-fidelity indicator when PowerShell processes spawn with `-EncodedCommand` parameters, especially in environments where this isn't common administrative behavior.

## What This Dataset Contains

This dataset captures a complete execution chain of base64-encoded PowerShell obfuscation. The Security channel shows the full process tree with command lines:

1. Initial PowerShell process (PID 3260) executes the encoding script: `powershell.exe` followed by a script block that creates the encoded command
2. Child PowerShell process (PID 6316) executes the actual obfuscation: `"powershell.exe" & {$OriginalCommand = 'Write-Host \"Hey, Atomic!\"' ... powershell.exe -EncodedCommand $EncodedCommand}`
3. Final PowerShell process (PID 7212) executes the decoded command: `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkALAAgAEEAdABvAG0AaQBjACEAIgA=`

The PowerShell channel contains the actual script blocks being executed, including the encoding logic and the final decoded command `Write-Host "Hey, Atomic!"`. Sysmon ProcessCreate events (EID 1) capture all three PowerShell processes in the chain, while ProcessAccess events (EID 10) show the parent processes accessing their children during execution.

The base64 string `VwByAGkAdABlAC0ASABvAHMAdAAgACIASABlAHkALAAgAEEAdABvAG0AaQBjACEAIgA=` decodes to the UTF-16LE representation of `Write-Host "Hey, Atomic!"`.

## What This Dataset Does Not Contain

This dataset represents a successful execution with no blocking or filtering. Windows Defender was active but did not intervene, likely because the payload is benign. The dataset doesn't show what would happen if more suspicious commands were encoded, or if AMSI (Antimalware Scan Interface) detected the decoded content.

Some Sysmon ProcessCreate events may be missing for non-suspicious child processes due to the include-mode filtering configuration. The PowerShell channel contains minimal test framework boilerplate beyond the actual technique execution, which is typical for focused test executions.

Network connections, file writes beyond PowerShell profile updates, or registry modifications are not present because this specific technique only demonstrates command encoding and execution without additional persistence or lateral movement activities.

## Assessment

This dataset provides excellent telemetry for detecting base64-encoded PowerShell obfuscation. The combination of Security 4688 events with full command-line logging and PowerShell script block logging creates multiple detection opportunities across different data sources.

The process chain visibility is particularly strong, showing the characteristic pattern of PowerShell spawning PowerShell with encoded commands. The PowerShell channel captures both the encoding process and the final decoded execution, while Sysmon adds process relationship context and access patterns.

For detection engineering, this data demonstrates why command-line logging is critical for PowerShell-based attacks, and how script block logging provides decoded visibility even when commands are obfuscated. The dataset would be even stronger with network telemetry to show potential follow-on activities that encoded commands often enable.

## Detection Opportunities Present in This Data

1. PowerShell process execution with `-EncodedCommand` parameter detected in Security 4688 command lines
2. Base64 strings in PowerShell command lines matching the characteristic length and character patterns of encoded commands
3. PowerShell script blocks containing `[System.Text.Encoding]::Unicode.GetBytes()` and `[Convert]::ToBase64String()` functions
4. Process chains showing PowerShell spawning additional PowerShell instances within short time windows
5. Sysmon ProcessAccess events (EID 10) showing PowerShell processes accessing newly created PowerShell child processes
6. PowerShell CommandInvocation events (4103) showing execution of decoded commands that don't match the original command line
7. Multiple PowerShell processes with different process GUIDs but same parent lineage executing in sequence
8. Named pipe creation patterns (`\PSHost.*powershell`) indicating PowerShell host initialization for obfuscated execution
9. PowerShell profile file access patterns coinciding with encoded command execution
10. Correlation between script block logging showing encoding functions and subsequent process creation with encoded parameters
