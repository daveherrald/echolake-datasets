# T1003.001-12: LSASS Memory — Dump LSASS.exe using imported Microsoft DLLs

## Technique Context

T1003.001 (LSASS Memory) is a critical credential access technique where attackers extract credentials from the Local Security Authority Subsystem Service (lsass.exe) process memory. This technique is fundamental to lateral movement and privilege escalation in Windows environments, as LSASS contains plaintext passwords, NTLM hashes, and Kerberos tickets for recently authenticated users.

The detection community focuses heavily on monitoring process access to LSASS with suspicious access rights, the creation of LSASS memory dumps, and the execution of known credential dumping tools. The "imported Microsoft DLLs" variant of this test uses legitimate Windows libraries (like dbghelp.dll and dbgcore.dll) to create memory dumps, making it harder to detect than traditional tools like Mimikatz or ProcDump since it relies on native Windows functionality.

## What This Dataset Contains

This dataset captures the execution of a custom tool (`xordump.exe`) that uses imported Microsoft DLLs to dump LSASS memory. The key telemetry includes:

**Process Execution Chain**: Security event 4688 shows PowerShell spawning another PowerShell instance with command line `"powershell.exe" & {C:\Windows\Temp\xordump.exe -out C:\Windows\Temp\lsass-xordump.t1003.001.dmp -x 0x41}`, executed as NT AUTHORITY\SYSTEM.

**PowerShell Script Block Logging**: Event 4104 captures the actual command being executed: `& {C:\Windows\Temp\xordump.exe -out C:\Windows\Temp\lsass-xordump.t1003.001.dmp -x 0x41}`, showing the tool being invoked to create an XOR-encoded memory dump.

**Sysmon Process Creation**: Event 1 captures the creation of both PowerShell instances and a `whoami.exe` process, providing detailed process ancestry and command-line arguments.

**Process Access Events**: Sysmon event 10 shows PowerShell (PID 6152) accessing other processes including `whoami.exe` (PID 5264) and another PowerShell instance (PID 2192) with full access rights (0x1FFFFF).

**Privilege Escalation**: Security event 4703 documents extensive privilege enablement for the PowerShell process, including SeDebugPrivilege-equivalent rights like SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, and others necessary for memory access.

## What This Dataset Does Not Contain

The dataset is missing several critical pieces of telemetry that would be expected from a successful LSASS dump:

**No LSASS Process Access**: Despite the tool's intent to dump LSASS memory, there are no Sysmon event 10 records showing direct process access to lsass.exe. This suggests Windows Defender may have blocked the actual LSASS access attempt before it occurred.

**No xordump.exe Execution**: The custom dumping tool itself never appears in process creation events (Sysmon event 1), indicating it was likely blocked by real-time protection before execution.

**Missing File Creation**: There's no evidence of the target dump file `C:\Windows\Temp\lsass-xordump.t1003.001.dmp` being created, as would be expected from a successful memory dump operation.

**Limited Process Tree**: The sysmon-modular configuration's include-mode filtering for ProcessCreate events means we only see certain processes (PowerShell, whoami.exe) but miss the execution of the actual dumping tool.

## Assessment

This dataset provides excellent telemetry for detecting the setup and attempted execution of LSASS dumping tools, but lacks the critical evidence of successful credential access due to Windows Defender's intervention. The Security channel's command-line logging and PowerShell's script block logging capture the attack intent clearly, while Sysmon provides detailed process relationships and access patterns.

The telemetry is particularly valuable for understanding how attackers use PowerShell to orchestrate credential dumping attempts and the privilege escalation patterns associated with such activities. However, the absence of actual LSASS interaction limits its utility for detecting successful credential theft.

## Detection Opportunities Present in This Data

1. **PowerShell Command Line Analysis**: Detect PowerShell executing external tools with memory dump-related parameters (`-out`, `.dmp` extensions, XOR encoding flags like `-x 0x41`)

2. **Suspicious Process Access Patterns**: Monitor Sysmon event 10 for PowerShell processes accessing other processes with full access rights (0x1FFFFF), especially when combined with credential dumping tool execution attempts

3. **Privilege Escalation Monitoring**: Alert on Security event 4703 showing extensive privilege enablement (SeBackupPrivilege, SeSecurityPrivilege, etc.) by PowerShell processes

4. **Script Block Hunting**: Use PowerShell event 4104 to identify script blocks containing memory dumping tool invocation patterns, custom executables with dump-related parameters

5. **Temp Directory Tool Execution**: Monitor for execution of unsigned executables from temporary directories (C:\Windows\Temp\) with names suggesting credential access functionality

6. **Process Tree Anomalies**: Detect PowerShell spawning additional PowerShell instances specifically for tool execution, which may indicate process injection or evasion attempts

7. **Failed Tool Execution Patterns**: Look for command-line evidence of credential dumping tools combined with the absence of expected file artifacts, indicating blocked or failed attempts
