# T1006-1: Direct Volume Access — Read volume boot sector via DOS device path (PowerShell)

## Technique Context

T1006 Direct Volume Access is a defense evasion technique where attackers bypass the standard file system API by directly reading physical storage devices through low-level interfaces. This technique allows bypassing file-based security controls like access control lists, file monitoring solutions, and some EDR products that monitor high-level file operations. Attackers commonly use this for sensitive data extraction, forensic artifact recovery, or bypassing file-based detections. The detection community focuses on monitoring direct access to physical device objects (like `\\.\C:`, `\\.\PhysicalDrive0`), unusual process access to raw disk sectors, and PowerShell or native APIs that interact with storage devices at the physical level.

## What This Dataset Contains

This dataset captures a successful PowerShell-based direct volume access attack that reads the boot sector of the C: drive. The core malicious activity appears in Security EID 4688, showing PowerShell spawning with the command: `"powershell.exe" & {$buffer = New-Object byte[] 11; $handle = New-Object IO.FileStream \""\\.\C:\"", 'Open', 'Read', 'ReadWrite'; $handle.Read($buffer, 0, $buffer.Length); $handle.Close(); Format-Hex -InputObject $buffer}`. 

PowerShell EID 4103 and 4104 events show the detailed execution, including `New-Object IO.FileStream "\\.\C:", 'Open', 'Read', 'ReadWrite'` creating a direct file handle to the raw C: drive device. The script successfully reads 11 bytes from the boot sector, as evidenced by the PowerShell EID 4103 Write-Output event showing the actual boot sector data: `"00000000   EB 52 90 4E 54 46 53 20 20 20 20                 ëRNTFS         "` - clearly showing the NTFS file system signature.

Sysmon EID 1 events capture the process creation chain: parent PowerShell (PID 888) spawning child PowerShell (PID 6216) with the malicious command line. No Sysmon EID 11 file access events are generated for the raw device access, confirming that direct volume access bypasses standard file monitoring.

## What This Dataset Does Not Contain

The dataset lacks any indication that Windows Defender detected or blocked this activity - all processes exit with status 0x0, indicating successful execution. There are no Windows Defender quarantine events, AMSI blocks, or error conditions in the PowerShell execution. The technique completed successfully without triggering endpoint protection.

Sysmon's file monitoring (EID 11) only captures PowerShell profile file creations, not the direct device access, demonstrating how this technique evades file-based monitoring. The dataset also doesn't contain any registry modifications or network activity, as this is purely a local disk access technique.

## Assessment

This dataset provides excellent telemetry for detecting T1006 Direct Volume Access via PowerShell. The Security 4688 events with command-line logging are the strongest detection source, clearly showing the `\\.\C:` device path access pattern. PowerShell logging provides rich context with both script block logging (EID 4104) capturing the full malicious code and module logging (EID 4103) showing the specific .NET FileStream API calls.

The combination of process creation telemetry, PowerShell script visibility, and successful technique execution makes this dataset highly valuable for detection engineering. The lack of EDR blocking allows for clean technique artifacts without the complications of partial execution or error conditions.

## Detection Opportunities Present in This Data

1. **Command Line Analysis** - Security EID 4688 showing PowerShell processes with `\\.\[Drive]:` device path patterns in command lines
2. **PowerShell Script Block Detection** - PowerShell EID 4104 containing `IO.FileStream` instantiation with raw device paths like `\\.\C:`
3. **PowerShell Module Invocation** - PowerShell EID 4103 New-Object calls with TypeName "IO.FileStream" and device path arguments
4. **Process Chain Analysis** - PowerShell spawning child PowerShell processes with device access parameters
5. **PowerShell API Pattern Matching** - Sequences of New-Object byte array creation followed by FileStream device access and Read operations
6. **Boot Sector Data Extraction** - PowerShell Format-Hex operations producing structured hex output of raw disk data
7. **Privilege Escalation Context** - System-level PowerShell processes performing direct storage access operations
