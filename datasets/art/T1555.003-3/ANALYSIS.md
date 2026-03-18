# T1555.003-3: Credentials from Web Browsers — LaZagne - Credentials from Browser

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) covers adversary techniques that extract saved passwords from browser credential stores. LaZagne is an open-source, Python-compiled credential recovery tool that targets dozens of applications including Chrome, Firefox, Opera, Edge, and Internet Explorer. It accesses browser SQLite databases and Windows DPAPI-protected blobs to recover plaintext credentials without requiring a browser to be running. It is widely used in post-exploitation toolkits and has been observed in ransomware precursor activity, targeted intrusion campaigns, and commodity malware.

## What This Dataset Contains

This dataset captures the execution attempt of LaZagne targeting browser credentials on a domain-joined Windows 11 workstation running as NT AUTHORITY\SYSTEM.

**Process execution chain (Security 4688):**
- `powershell.exe` spawned `whoami.exe` (ART test framework identity check)
- `powershell.exe` spawned `cmd.exe` with: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1555.003\bin\LaZagne.exe" browsers`

**Sysmon process create (EID=1):**
- `whoami.exe` tagged `technique_id=T1033` (System Owner/User Discovery)
- `cmd.exe` launching LaZagne tagged `technique_id=T1059.003` (Windows Command Shell)

**Sysmon process access (EID=10):**
- Two EID=10 events show `powershell.exe` accessing child `cmd.exe` and its subprocess, tagged `technique_id=T1055.001` (DLL Injection) — this is the sysmon-modular rule heuristic firing on cross-process handle acquisition during process spawning, not actual injection.

**Sysmon image loads (EID=7):**
- Multiple DLLs loaded into the parent `powershell.exe` process: `mscoree.dll`, .NET framework assemblies, tagged with T1055 (Process Injection) and T1574.002 (DLL Side-Loading) rule names from the sysmon-modular config.

**Sysmon named pipe (EID=17):**
- `\PSHost.*` pipes created by PowerShell — standard PowerShell console host infrastructure.

**Sysmon file create (EID=11):**
- `StartupProfileData-Interactive` written to the SYSTEM profile — standard PowerShell startup artifact.

**Security exit codes:**
- `cmd.exe` exited with `0x1` (failure), indicating LaZagne was blocked or failed. Windows Defender terminated or prevented the process from completing successfully.

**PowerShell (4103/4104):**
- Module logging shows `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — the ART test framework standard setup invocation, repeated across multiple parallel PowerShell instances.
- No 4104 script blocks containing LaZagne logic appear; the tool was invoked directly as a binary via cmd.exe, not through PowerShell script.

## What This Dataset Does Not Contain (and Why)

**LaZagne process creation in Sysmon:** LaZagne.exe does not appear as an EID=1 event. The sysmon-modular config uses include-mode ProcessCreate filtering — LaZagne's binary name does not match any of the LOLBin or suspicious-pattern include rules, so no Sysmon EID=1 was generated for it. Security 4688 captured it because command-line auditing is configured for all processes.

**Successful credential extraction:** The `cmd.exe` exit code of `0x1` confirms the attempt failed. Windows Defender (version 4.18.26010.5, signatures 1.445.536.0) blocked LaZagne before it could read browser stores. No file writes to browser credential paths appear in EID=11.

**DPAPI or browser database access:** No object access events (audit policy has object access disabled). No file read events. No registry access events.

**Network connections:** LaZagne operates entirely locally; no network telemetry is expected or present.

## Assessment

Windows Defender blocked the LaZagne execution — the dataset reflects an attempted, not successful, credential theft. The value lies in what is captured despite the block: the full command line in Security 4688 (`"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1555.003\bin\LaZagne.exe" browsers`), the process lineage from SYSTEM PowerShell, and the exit code indicating failure. The absence of LaZagne in Sysmon EID=1 is a real-world gap that defenders encounter with include-mode filtering — Security 4688 with command-line auditing fills that gap here.

## Detection Opportunities Present in This Data

- **Security 4688** with command-line auditing captures `LaZagne.exe browsers` with full path; this is the primary detection signal. Rule: alert on processes with image names or command lines matching `LaZagne`.
- **Security 4689** exit code `0x1` for `cmd.exe` correlates with the blocked attempt — exit codes from credential tool wrappers can indicate AV interference.
- **Sysmon EID=1** tagged `T1059.003` on `cmd.exe` from a PowerShell parent running as SYSTEM is suspicious even without tool-specific signatures.
- **Sysmon EID=10** (process access) showing PowerShell opening handles to cmd.exe subprocesses from SYSTEM context is a secondary signal worth baselining.
- **PowerShell 4103** showing `Set-ExecutionPolicy Bypass` with `User = ACME\SYSTEM` is a consistent test framework artifact in this dataset; in production it would indicate automated execution from a SYSTEM-context shell.
