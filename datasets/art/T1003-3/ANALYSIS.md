# T1003-3: OS Credential Dumping — Dump svchost.exe to gather RDP credentials

## Technique Context

T1003.003 (OS Credential Dumping: NTDS) is a critical credential access technique where attackers target Windows credential repositories for password hashes, Kerberos tickets, and plaintext credentials. While this dataset focuses on dumping svchost.exe rather than NTDS specifically, it demonstrates a common memory dumping approach used against various Windows processes to extract sensitive authentication material.

The detection community prioritizes monitoring for process memory access patterns, especially targeting of security-sensitive processes like LSASS, services hosting RDP connections, and credential storage mechanisms. Key detection indicators include suspicious process access with high privileges (0x1FFFFF), use of legitimate tools like rundll32.exe with comsvcs.dll for memory dumping, and creation of dump files in temporary locations.

This particular technique variation targets svchost.exe processes, potentially to extract RDP session credentials or other service-hosted authentication material. The technique uses PowerShell to identify target processes and leverages the legitimate Windows COM+ Services DLL (comsvcs.dll) through rundll32.exe to create process memory dumps.

## What This Dataset Contains

The dataset captures a successful memory dumping operation with clear telemetry of the attack chain:

**PowerShell Command Execution**: Security event 4688 shows the key PowerShell command: `"powershell.exe" & {$ps = (Get-NetTCPConnection -LocalPort 3389 -State Established -ErrorAction Ignore); if($ps){$id = $ps[0].OwningProcess} else {$id = (Get-Process svchost)[0].Id }; C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $id $env:TEMP\svchost-exe.dmp full}`

**Process Reconnaissance**: PowerShell events 4103 show `Get-NetTCPConnection -LocalPort 3389 -State Established` (looking for RDP connections) and `Get-Process svchost` (enumerating svchost processes).

**Memory Dumping Execution**: Security event 4688 captures rundll32.exe execution with command line `"C:\Windows\System32\rundll32.exe" C:\windows\System32\comsvcs.dll MiniDump 364 C:\Windows\TEMP\svchost-exe.dmp full`.

**Process Memory Access**: Sysmon event 10 records the critical process access: `SourceImage: C:\Windows\System32\rundll32.exe`, `TargetProcessId: 364`, `TargetImage: C:\Windows\system32\svchost.exe`, `GrantedAccess: 0x1FFFFF` with rule name `technique_id=T1003,technique_name=Credential Dumping`.

**DLL Loading**: Sysmon event 7 shows rundll32.exe loading `C:\Windows\System32\comsvcs.dll` with rule name `technique_id=T1003.004,technique_name=LSASS Memory`.

**Dump File Creation**: Sysmon event 11 captures file creation: `TargetFilename: C:\Windows\Temp\svchost-exe.dmp` by rundll32.exe process.

## What This Dataset Does Not Contain

The dataset lacks post-dump activity telemetry - no events showing the dump file being read, parsed, or exfiltrated. The PowerShell events primarily contain execution policy changes and framework boilerplate rather than the core attack logic. 

No network connections are captured that might indicate credential extraction tools connecting to the dump file or exfiltration attempts. The dataset also doesn't show any defensive responses from Windows Defender, suggesting the technique executed without endpoint protection interference.

Missing are any events showing what credentials were actually extracted from the dump or subsequent lateral movement attempts using discovered credentials.

## Assessment

This dataset provides excellent detection engineering value for memory dumping techniques. The telemetry clearly demonstrates the complete attack chain from reconnaissance (checking for RDP connections) through execution (rundll32.exe + comsvcs.dll) to artifact creation (dump file).

The Security 4688 events with command-line logging capture the full attack methodology, while Sysmon events 1, 7, 10, and 11 provide rich process creation, DLL loading, process access, and file creation telemetry. The combination gives defenders multiple detection opportunities across different log sources.

The process access event with 0x1FFFFF permissions against svchost.exe is particularly valuable, as this specific access pattern combined with rundll32.exe is highly indicative of credential dumping attempts. The presence of both Security audit logs and Sysmon data allows for robust detection rule development and validation.

## Detection Opportunities Present in This Data

1. **Memory Dumping via rundll32.exe + comsvcs.dll**: Security 4688 events showing rundll32.exe with command lines containing "comsvcs.dll" and "MiniDump" parameters

2. **Suspicious Process Access Patterns**: Sysmon event 10 showing rundll32.exe accessing svchost.exe with 0x1FFFFF (PROCESS_ALL_ACCESS) permissions

3. **PowerShell Reconnaissance Commands**: PowerShell events 4103/4104 containing "Get-NetTCPConnection -LocalPort 3389" or "Get-Process svchost" indicating target identification

4. **Dump File Creation in Temp Directories**: Sysmon event 11 showing .dmp file creation in %TEMP% or other temporary locations by rundll32.exe

5. **Comsvcs.dll Loading by rundll32.exe**: Sysmon event 7 showing rundll32.exe loading comsvcs.dll, especially when combined with subsequent process access

6. **PowerShell Process Chain with rundll32.exe Child**: Security 4688 parent-child relationships showing PowerShell spawning rundll32.exe with memory dumping parameters

7. **Multiple Process Access Events**: Clustering of Sysmon event 10 records showing systematic process enumeration and access by PowerShell or rundll32.exe
