# T1055.012-4: Process Hollowing — T1055.012

## Technique Context

Process Hollowing (T1055.012) is a sophisticated process injection technique where an attacker creates a legitimate process in a suspended state, unmaps its original memory image, and replaces it with malicious code. This technique is particularly effective for defense evasion because the malicious code executes within the context of a legitimate process, making detection more challenging. Attackers commonly use this technique to execute payloads while appearing to run legitimate processes like svchost.exe, explorer.exe, or other trusted system binaries.

The detection community focuses heavily on process creation with unusual parent-child relationships, process access events with high privileges (especially PROCESS_ALL_ACCESS), and memory manipulation APIs like NtUnmapViewOfSection, VirtualAllocEx, and WriteProcessMemory. This particular test implements process hollowing in Go using the CreateProcessW API with the CREATE_SUSPENDED flag and CreatePipe for inter-process communication.

## What This Dataset Contains

This dataset captures a Go-based process hollowing implementation targeting `werfault.exe` (Windows Error Reporting fault tolerant heap). The primary evidence includes:

**Process Creation Chain**: Security 4688 shows the PowerShell command line `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcessWithPipe.exe -program \"C:\Windows\System32\werfault.exe\" -debug}` executed by PID 28860.

**Process Access Events**: Sysmon EID 10 captures two critical process access events from PowerShell (PID 34976) targeting:
- `whoami.exe` (PID 34904) with GrantedAccess `0x1FFFFF` (PROCESS_ALL_ACCESS)
- Another PowerShell instance (PID 28860) with GrantedAccess `0x1FFFFF`

The CallTrace for these access events shows .NET Framework execution paths through `System.Management.Automation.ni.dll`, indicating PowerShell's involvement in the injection process.

**Named Pipe Creation**: Sysmon EID 17 documents PowerShell host pipes: `\PSHost.134178993525277899.34976.DefaultAppDomain.powershell` and `\PSHost.134178993536256520.28860.DefaultAppDomain.powershell`.

**Script Block Evidence**: PowerShell EID 4104 captures the execution command: `C:\AtomicRedTeam\atomics\T1055.012\bin\x64\CreateProcessWithPipe.exe -program "C:\Windows\System32\werfault.exe" -debug`.

## What This Dataset Does Not Contain

The dataset lacks several key indicators typically associated with process hollowing:

**No Sysmon ProcessCreate for the Injector**: The Go-based `CreateProcessWithPipe.exe` executable doesn't appear in Sysmon EID 1 events because the sysmon-modular configuration uses include-mode filtering that doesn't capture this custom executable.

**Missing Target Process Creation**: No Sysmon ProcessCreate event for `werfault.exe` appears, suggesting the process hollowing may have failed or the target was cleaned up before Sysmon could log it.

**No Memory Manipulation Events**: The dataset contains no Sysmon EID 8 (CreateRemoteThread) events or additional process access events showing memory writing operations typical of successful process hollowing.

**Limited File System Activity**: Only PowerShell profile cache files appear in Sysmon EID 11, with no evidence of payload drops or executable modifications.

## Assessment

This dataset provides moderate utility for detection engineering, primarily capturing the execution attempt rather than successful process hollowing. The Security 4688 events with full command-line logging provide excellent visibility into the attack initiation, while Sysmon EID 10 process access events offer the strongest technical evidence of injection attempts. However, the absence of the actual injector process creation and target process telemetry limits the dataset's completeness.

The PowerShell script block logging successfully captures the attack command, making this dataset valuable for PowerShell-based detection rules. The process access events with PROCESS_ALL_ACCESS from PowerShell to system utilities like `whoami.exe` represent high-fidelity indicators of process injection attempts.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Detection**: Alert on PowerShell executing custom executables with `-program` and `-debug` parameters, especially when targeting Windows system binaries like `werfault.exe`.

2. **Process Access with Full Permissions**: Create alerts for Sysmon EID 10 events where PowerShell processes access other processes with GrantedAccess `0x1FFFFF` (PROCESS_ALL_ACCESS).

3. **PowerShell Script Block Analysis**: Monitor PowerShell EID 4104 for script blocks containing references to custom executables in `\AtomicRedTeam\atomics\` paths or similar testing directories.

4. **Unusual Process Parent-Child Relationships**: Detect PowerShell processes spawning from other PowerShell instances with command lines containing external executable invocation patterns.

5. **Named Pipe Correlation**: Correlate PowerShell host pipe creation (Sysmon EID 17) with subsequent process access events to identify potential injection workflows.

6. **Cross-Process CallTrace Analysis**: Analyze CallTrace fields in Sysmon EID 10 events showing .NET Framework paths originating from PowerShell processes targeting system utilities.
