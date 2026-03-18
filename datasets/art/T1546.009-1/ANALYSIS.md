# T1546.009-1: AppCert DLLs — Create Registry Persistence via AppCert DLL

## Technique Context

T1546.009 (AppCert DLLs) is a persistence mechanism that exploits the Windows `AppCertDlls` registry key under `HKLM\System\CurrentControlSet\Control\Session Manager\`. Any DLL listed here is loaded into every process that calls the Win32 API functions `CreateProcess`, `CreateProcessAsUser`, `CreateProcessWithLoginW`, `CreateProcessWithTokenW`, or `WinExec`. This makes it an extremely broad persistence hook — the malicious DLL executes in the context of virtually every new process on the system. The technique is used to achieve process injection-style persistence that survives reboots and runs silently. It requires elevation to write the registry key. Detection focuses on modifications to the `AppCertDlls` key, and on DLL files placed in writable locations that are referenced from that key.

## What This Dataset Contains

This is the richest dataset in this collection in terms of overlapping detection artifacts. The test copies a DLL (`AtomicTest.dll`) to `C:\Users\Public\` and then registers it under `AppCertDlls`.

**Sysmon EID 13 (RegistryValueSet)** captures the persistence registration directly:

```
RuleName: technique_id=T1546.009,technique_name=AppCert DLLs
TargetObject: HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls\AtomicTest
Details: C:\Users\Public\AtomicTest.dll
Image: C:\Windows\system32\reg.exe
```

**Sysmon EID 11 (FileCreate)** captures the DLL being placed:

```
RuleName: technique_id=T1047,technique_name=File System Permissions Weakness
TargetFilename: C:\Users\Public\AtomicTest.dll
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Sysmon EID 29 (FileExecutableDetected)** is present — Sysmon flagged the creation of an executable file:

```
RuleName: technique_id=T1059.001,technique_name=PowerShell
TargetFilename: C:\Users\Public\AtomicTest.dll
Hashes: SHA1=E61787BB2A87B0D0B605362F3A50CCD27084D401,MD5=7E8EE7A7374AEE5B0F322C6A2F50FD3A,SHA256=FAD925CCD655FD3F23FE4853959A7AB55690690957C8F8C3FFF482C02B5459B2,IMPHASH=334BAC200CD4B92DAAE32341A39EF3F0
```

**PowerShell EID 4104 (ScriptBlock)** contains the actual test script — this is one of the few datasets in this collection where substantive technique content appears in the PowerShell channel:

```powershell
Copy-Item "C:\AtomicRedTeam\atomics\T1546.009\bin\AtomicTest.dll" C:\Users\Public\AtomicTest.dll -Force
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\AppCertDlls" /v "AtomicTest" /t REG_EXPAND_SZ /d "C:\Users\Public\AtomicTest.dll" /f
if($false){Restart-Computer}
```

Sysmon EID 3 (NetworkConnect) appears for `MpDefenderCoreService.exe` making an outbound TCP connection hours after the test — a Defender telemetry upload, not related to the technique.

Security EID 4688 shows three process creations: `whoami.exe`, `powershell.exe` (a child spawned to run the reg command inline), and `reg.exe`. EID 4689 shows eight process terminations. One EID 4703 is present.

## What This Dataset Does Not Contain

The DLL itself is not executed during this test (the `if($false){Restart-Computer}` branch never fires). There is no evidence of `AppCertDlls` triggering — the DLL would load the next time a new process is created, which does not happen within the test window. Therefore there is no process injection event, no DLL load (EID 7) from `C:\Users\Public\AtomicTest.dll`, and no downstream network or behavior artifacts from the DLL payload. The test registers persistence only; execution is deferred to future process creation.

## Assessment

This is an excellent dataset for AppCert DLL persistence detection. Three independent artifacts are present: the EID 13 registry write (tagged with the correct T1546.009 technique), the EID 11 DLL file creation in a user-writable path, and the EID 29 executable-file-detected alert. The PowerShell EID 4104 script block provides a complete view of the attacker's intent and exact registry path. The full SHA hashes in EID 29 enable IOC correlation. The deferred DLL execution means this dataset covers the setup phase well; pairing it with execution-phase coverage would require a separate dataset with a process creation following the reboot or the next process launch.

## Detection Opportunities Present in This Data

1. **Sysmon EID 13 — RegistryValueSet to `HKLM\System\CurrentControlSet\Control\Session Manager\AppCertDlls\*`** with a DLL path in a user-writable location (`C:\Users\Public\`) — tagged `T1546.009`.
2. **Sysmon EID 11 — DLL file dropped in `C:\Users\Public\`** by `powershell.exe` as SYSTEM, within the same second as the `AppCertDlls` registry write.
3. **Sysmon EID 29 — FileExecutableDetected for a DLL written to `C:\Users\Public\`** — executable in a world-writable directory, with full hash for IOC correlation.
4. **PowerShell EID 4104 — ScriptBlock containing `reg add ... AppCertDlls`** — full command including registry path and DLL path, enables string-based detection.
5. **Security EID 4688 — `reg.exe` invocation as SYSTEM** with a command line targeting `AppCertDlls`, corroborating the Sysmon registry write.
6. **Correlation: EID 11 DLL drop in `C:\Users\Public\` + EID 13 `AppCertDlls` write within the same second** — co-occurrence of DLL placement and persistence registration is a high-confidence behavioral cluster.
