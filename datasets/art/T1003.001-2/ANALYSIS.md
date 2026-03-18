# T1003.001-2: LSASS Memory — Dump LSASS.exe Memory using comsvcs.dll

## Technique Context

T1003.001 (OS Credential Dumping: LSASS Memory) is one of the most consequential techniques in enterprise intrusions. The Local Security Authority Subsystem Service (lsass.exe) holds plaintext passwords, NTLM hashes, and Kerberos tickets in memory. Dumping it gives an attacker lateral movement capability across the entire domain.

This test uses the comsvcs.dll variant — a pure Living Off the Land (LOLBin) approach. Every Windows system ships with `C:\Windows\System32\comsvcs.dll`, which exports a `MiniDump` function. By calling `rundll32.exe comsvcs.dll, MiniDump <lsass_pid> <outfile> full`, an attacker can dump LSASS memory without bringing any external tools onto disk. This makes it a favorite of both commodity malware and sophisticated threat actors.

The detection community has converged on several primary indicators for this technique:

- **Sysmon EID 10 (ProcessAccess)** targeting `lsass.exe` with suspicious GrantedAccess masks (0x1010, 0x1410, 0x1FFFFF) — this is the foundation of most Sigma rules for LSASS dumping
- **Sysmon EID 1 / Security 4688** showing `rundll32.exe` with `comsvcs.dll` and `MiniDump` in the command line
- **Sysmon EID 11 (FileCreate)** for the dump file being written to disk

## What This Dataset Contains

The strongest evidence in this dataset is a **Security 4688 (Process Creation)** event with the full command line:

```
"powershell.exe" & {C:\Windows\System32\rundll32.exe C:\windows\System32\comsvcs.dll,
MiniDump (Get-Process lsass).id $env:TEMP\lsass-comsvcs.dmp full}
```

This is exactly the kind of command-line artifact that a detection rule can match with high confidence — `comsvcs.dll` + `MiniDump` + `lsass` in a process creation event. Any environment with command-line auditing enabled (Security 4688) will capture this.

The Security channel also contains a **4703 (Token Right Adjusted)** event showing the parent PowerShell process enabling SeDebugPrivilege-adjacent privileges — a prerequisite for accessing LSASS memory and itself an independent detection opportunity.

The Sysmon channel captured a **CreateRemoteThread (EID 8)** from PowerShell into another process, and standard .NET/PowerShell startup DLL loads. The PowerShell channel contains `Set-ExecutionPolicy Bypass` (the test framework setup) and internal PowerShell error-formatting scriptblocks — no technique-specific content.

## What This Dataset Does Not Contain

The technique was **blocked by Windows Defender**. The child process exited with status `0xC0000022` (STATUS_ACCESS_DENIED), meaning the MiniDump call never reached LSASS. This has significant implications for the telemetry:

**No Sysmon EID 10 (ProcessAccess) targeting lsass.exe.** This is what the majority of production detection rules key on. Because Defender intercepted the technique before `rundll32.exe` could open a handle to lsass.exe, this event was never generated. Detection engineers building rules exclusively from this dataset would miss the handle-access pattern that works even when attackers obfuscate their command lines.

**No Sysmon EID 1 (ProcessCreate) for rundll32.exe.** The LOLBin process creation is absent from Sysmon entirely — it appears only in Security 4688. This likely means rundll32 never fully spawned, or the Sysmon configuration's ProcessCreate filter didn't capture it.

**No Sysmon EID 11 (FileCreate) for the dump file.** Since the dump was blocked, `lsass-comsvcs.dmp` was never written. This absence is expected and consistent.

**The PowerShell channel has no technique content.** The actual technique command was dispatched via `cmd.exe /c powershell.exe`, so the inner PowerShell session was killed by AMSI before ScriptBlock Logging could capture the Invoke-AtomicTest payload.

## Assessment

This dataset captures a **blocked credential dumping attempt**, not a successful one. The Security 4688 command line is the primary detection artifact, and it's a good one — the verbatim `comsvcs.dll, MiniDump` string is present and matchable. The blocked-attempt pattern is also realistic, since most enterprise environments have Defender or equivalent EDR active.

However, detection engineers should be aware that the deeper behavioral telemetry — LSASS handle access patterns, dump file creation, comsvcs.dll ImageLoad into rundll32 — is absent here. Rules built solely on command-line matching will catch unsophisticated usage of this technique but will miss variants where the attacker obfuscates the command line or uses direct API calls. For complete LSASS access detection coverage, this dataset should be paired with a successful-execution variant where the dump completes and generates the full ProcessAccess/FileCreate chain.

## Detection Opportunities Present in This Data

1. **Command-line pattern matching** (Security 4688): Match process creation events where the command line contains `comsvcs.dll` and `MiniDump`. High confidence, low false-positive rate.

2. **Privilege escalation** (Security 4703): PowerShell enabling SeLoadDriverPrivilege, SeSecurityPrivilege, SeTakeOwnershipPrivilege, and SeBackupPrivilege simultaneously. Unusual outside of system administration contexts.

3. **CreateRemoteThread from PowerShell** (Sysmon EID 8): PowerShell processes should rarely create remote threads. The target being `<unknown process>` (exited before Sysmon resolved the name) adds suspicion.

4. **Failed execution as signal** (Security 4689): An exit code of `0xC0000022` (STATUS_ACCESS_DENIED) on a process whose command line references security-sensitive operations is itself worth alerting on — it indicates an attempted attack that was blocked.
