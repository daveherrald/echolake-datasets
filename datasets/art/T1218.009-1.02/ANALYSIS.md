# T1218.009-1: Regsvcs/Regasm — Regasm Uninstall Method Call Test

## Technique Context

T1218.009 covers adversary abuse of two .NET assembly registration utilities: `RegAsm.exe` (Assembly Registration Utility) and `RegSvcs.exe` (.NET Component Services Registrar). Both are signed Microsoft binaries designed to register .NET assemblies for COM interop. However, they can be exploited to execute arbitrary code: when invoked with the `/U` (uninstall/unregister) flag, `regasm.exe` calls the `[ComUnregisterFunction]`-attributed method in the target assembly, allowing an attacker to execute code in the context of a trusted Microsoft binary.

The attack workflow in this test is notable because it includes a compilation step: a malicious `.cs` source file is compiled on-the-fly using `csc.exe` (the .NET C# compiler, another trusted Microsoft binary), producing a DLL that is then loaded by `regasm.exe`. This on-the-fly compilation from source approach evades file-based hash detections — there is no pre-compiled malicious binary to blacklist.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset contains 144 total events: 107 PowerShell, 7 Security, and 30 Sysmon.

**Security EID 4688 captures the full attack chain:**

1. `"cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"%tmp%\T1218.009.dll" /target:library "C:\AtomicRedTeam\atomics\T1218.009\src\T1218.009.cs" & C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U %tmp%\T1218.009.dll` — the combined compile+execute chain
2. `C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"C:\Windows\TEMP\T1218.009.dll" /target:library "C:\AtomicRedTeam\atomics\T1218.009\src\T1218.009.cs"` — compilation of the malicious assembly
3. `C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RES13EE.tmp" "c:\Windows\Temp\CSCC868B41CDB544194A3F713F4DDE53EA5.TMP"` — resource converter invoked by csc
4. `C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U C:\Windows\TEMP\T1218.009.dll` — regasm with /U (uninstall) flag executing the compiled DLL
5. `"C:\Windows\system32\whoami.exe"` — ATH framework success verification (two executions)
6. `"cmd.exe" /c del %tmp%\T1218.009.dll >nul 2>&1` — cleanup command

**Sysmon EID 1** captures the process creation events with parent-child relationships:
- `powershell.exe` → `cmd.exe` (the combined csc+regasm chain, `RuleName: technique_id=T1059.003`)
- `cmd.exe` → `csc.exe` (`CommandLine: C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"C:\Windows\TEMP\T1218.009.dll" /target:library "C:\AtomicRedTeam\atomics\T1218.009\src\T1218.009.cs"`, `RuleName: technique_id=T1127`)
- `powershell.exe` → two `whoami.exe` executions (`RuleName: technique_id=T1033`)
- Cleanup `cmd.exe` (`del %tmp%\T1218.009.dll`)

**Sysmon EID 11 (File Created)** records 5 file creation events documenting the compilation artifacts:
- The compiled DLL at `C:\Windows\Temp\T1218.009.dll`
- The csc temporary file `C:\Windows\Temp\CSCC868B41CDB544194A3F713F4DDE53EA5.TMP`
- PowerShell profile files

**Sysmon EID 10 (Process Access)** records 4 full-access events from PowerShell to `whoami.exe` and `cmd.exe`.

**Sysmon EID 7 (Image Load)** records 14 events for .NET runtime DLLs in the test framework PowerShell process.

**PowerShell EID 4104** captures test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass, $ErrorActionPreference) across 104 events, with 3 EID 4103 module logging events.

## What This Dataset Does Not Contain

Sysmon does not capture a `regasm.exe` process creation event. The sysmon-modular include-mode filter for ProcessCreate does not match `regasm.exe`, so its creation is only visible in Security EID 4688. This means the DLL loading behavior by `regasm.exe` (which would appear in Sysmon EID 7 as DLL image loads) is also absent — there is no Sysmon EID 7 entry showing the compiled `T1218.009.dll` being loaded by `regasm.exe`.

The `ComUnregisterFunction` code execution inside `regasm.exe` is not directly visible in any channel. Only its side effects (the `whoami.exe` executions) confirm execution.

No network events appear, consistent with a local compilation and execution workflow.

The cleanup command (`del %tmp%\T1218.009.dll`) appears in both Security 4688 and Sysmon EID 1, confirming the attacker tidied the compiled DLL artifact after use.

## Assessment

This dataset documents a successful undefended Regasm LOLBin execution with on-the-fly compilation. The complete attack workflow — compile from source, execute via `/U` flag, clean up — is preserved across Security EID 4688 events. The `whoami.exe` executions confirm the `ComUnregisterFunction` method ran successfully.

Compared to the defended variant (37 Sysmon, 16 Security, 34 PowerShell), this undefended run produced more events across all channels. The defended run had the same process chain structure; the undefended run's higher event counts likely reflect the absence of Defender interrupting the process flow.

A key observation: `csc.exe` compiling a DLL referencing `System.EnterpriseServices.dll` in combination with a subsequent `regasm.exe /U` invocation is a distinctive attack signature. The compilation step is not noise — it is part of the technique.

## Detection Opportunities Present in This Data

**Security EID 4688 (csc.exe):** The command line `csc.exe /r:System.EnterpriseServices.dll /out:...T1218.009.dll /target:library "...T1218.009.cs"` is highly actionable. `csc.exe` compiling an assembly with `/r:System.EnterpriseServices.dll` from a source file in a non-standard location, followed by `regasm.exe /U`, is the characteristic signature of this technique.

**Sysmon EID 1 (csc.exe):** Tagged `technique_id=T1127` (Trusted Developer Utilities Proxy Execution), this event fires on `csc.exe` being run from `cmd.exe` spawned by `powershell.exe`. The parent chain is anomalous for legitimate .NET compilation workflows.

**Sysmon EID 11 (File Created):** `C:\Windows\Temp\T1218.009.dll` creation from `csc.exe` is captured. File creation in temp directories by trusted compiler tools (csc, msbuild) should be scrutinized when the compilation references enterprise services or COM interop assemblies.

**Security EID 4688 (regasm.exe):** `regasm.exe /U C:\Windows\TEMP\T1218.009.dll` — the `/U` flag on a freshly-compiled DLL in a temp directory is the key indicator. `regasm.exe /U` pointing to anything outside of normal software installation paths is suspicious.

**Sysmon EID 10:** PowerShell full-access to `cmd.exe` and `whoami.exe` round out the behavioral chain for correlation with the Security events.
