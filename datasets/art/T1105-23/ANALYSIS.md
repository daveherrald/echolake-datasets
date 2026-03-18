# T1105-23: Ingress Tool Transfer — Lolbas replace.exe use to copy file

## Technique Context

T1105 (Ingress Tool Transfer) involves adversaries transferring tools or files from an external system into a compromised environment. This technique is fundamental to most attack chains, as adversaries need to bring their payloads, utilities, or data exfiltration tools onto target systems. The detection community focuses heavily on monitoring file transfers through various channels—network downloads, removable media, email attachments, and Living-off-the-Land Binary (LOLBin) abuse.

Replace.exe is a legitimate Windows utility designed to replace existing files with new versions, but it can be abused for ingress tool transfer. By using the /A flag (add mode), replace.exe will copy files to a destination even if they don't already exist, effectively functioning as a file copy utility. This makes it attractive to adversaries who want to transfer files using signed Windows binaries to evade detection systems focused on unsigned executables or suspicious network activity.

## What This Dataset Contains

This dataset captures the execution of replace.exe to copy a file from the Atomic Red Team test directory to the Windows temp folder. The key evidence includes:

**Process Chain (Security 4688):**
- PowerShell spawns cmd.exe: `"cmd.exe" /c del %TEMP%\redcanary.cab >nul 2>&1 & C:\Windows\System32\replace.exe "C:\AtomicRedTeam\atomics\T1105\src\redcanary.cab" %TEMP% /A`
- cmd.exe spawns replace.exe: `C:\Windows\System32\replace.exe "C:\AtomicRedTeam\atomics\T1105\src\redcanary.cab" C:\Windows\TEMP /A`

**Sysmon Process Creation (EID 1):**
- Sysmon captured the cmd.exe creation with the full command line showing the delete operation and replace.exe execution
- Sysmon captured replace.exe creation showing the source file path, destination directory, and the /A flag usage

**File Creation (Sysmon EID 11):**
- `C:\Windows\Temp\redcanary.cab` created by replace.exe process (PID 31008) at 2026-03-13 19:36:44.852
- The file creation event shows the technique successfully transferred the test file

**Process Access (Sysmon EID 10):**
- PowerShell accessed both the cmd.exe and replace.exe processes with full access rights (0x1FFFFF), indicating normal parent-child process interaction

## What This Dataset Does Not Contain

The dataset doesn't show the original file being read from the source location, as Sysmon file access events aren't configured in the collection setup. There's no network activity since this is a local file copy operation rather than a download. The technique completed successfully with exit status 0x0 for replace.exe, so there's no evidence of Windows Defender blocking or interfering with the operation. Registry modifications and additional persistence mechanisms aren't present since this test only demonstrates the file transfer capability.

## Assessment

This dataset provides excellent telemetry for detecting replace.exe abuse for ingress tool transfer. The combination of command-line logging in Security 4688 events and Sysmon ProcessCreate events gives complete visibility into the technique execution. The file creation event in Sysmon provides definitive proof of the file transfer outcome. The process chain from PowerShell to cmd.exe to replace.exe is fully documented, and the command-line arguments clearly show the /A flag abuse pattern.

The main limitation is the lack of file access telemetry showing the source file being read, but the command line arguments provide sufficient context. For real-world detection, this level of telemetry would enable reliable identification of replace.exe being used for file transfer operations.

## Detection Opportunities Present in This Data

1. **Replace.exe with /A flag usage** - Monitor Security 4688 or Sysmon EID 1 for replace.exe command lines containing "/A" parameter, which indicates add mode commonly abused for file copying
2. **Replace.exe writing to temp directories** - Detect replace.exe creating files in user or system temp locations via Sysmon EID 11, which may indicate file staging for malicious purposes
3. **Replace.exe spawned by scripting engines** - Monitor for replace.exe as child process of powershell.exe, cmd.exe, or other scripting hosts, especially with suspicious source/destination paths
4. **Replace.exe with external source paths** - Alert on replace.exe command lines referencing files outside of standard Windows directories, which may indicate transfer of external tools
5. **Process chain analysis** - Correlate replace.exe execution with parent process command lines that contain file manipulation commands (del, copy, move) suggesting orchestrated file transfer operations
