# T1127.001-1: MSBuild — MSBuild Bypass Using Inline Tasks (C#)

## Technique Context

T1127.001 MSBuild describes adversaries abusing `MSBuild.exe` — Microsoft's build engine for .NET applications — to execute arbitrary code embedded in XML project files. MSBuild supports "inline tasks" that allow arbitrary C# or VB.NET code to be embedded directly in `.csproj` or `.targets` files. When MSBuild processes these files, it compiles and executes the embedded code in-process.

This technique is powerful for several reasons: MSBuild is a Microsoft-signed binary that ships with the .NET Framework, it is frequently allowed by application whitelisting policies, and the malicious code lives entirely within a project file (an XML document) rather than a traditional executable. In a real attack, the `.csproj` file would contain inline task code that spawns a shell, downloads additional payloads, or injects code into another process.

This test uses the ART-supplied file `C:\AtomicRedTeam\atomics\T1127.001\src\T1127.001.csproj`, which contains a benign inline C# task. The execution chain is:

```
cmd.exe /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\T1127.001.csproj"
```

MSBuild processes the `.csproj`, invokes `csc.exe` (the C# compiler) to compile the inline task, uses `cvtres.exe` to build resource files, and then executes the compiled task in-process.

## What This Dataset Contains

The dataset captures 50 Sysmon events, 9 Security events, and 96 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

The full MSBuild compilation chain is recorded in Security EID 4688:

1. PowerShell spawns `cmd.exe`:
   ```
   "cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\T1127.001.csproj"
   ```

2. `cmd.exe` spawns `MSBuild.exe`:
   ```
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe  "C:\AtomicRedTeam\atomics\T1127.001\src\T1127.001.csproj"
   ```

3. `MSBuild.exe` spawns `csc.exe` (C# compiler) twice — once for each inline task compilation step:
   ```
   "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\jf0lifbf\jf0lifbf.cmdline"
   "C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe" /noconfig /fullpaths @"C:\Windows\SystemTemp\0q3d5pbl\0q3d5pbl.cmdline"
   ```

4. Each `csc.exe` invocation spawns `cvtres.exe`:
   ```
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RES3ABC.tmp" "c:\Windows\SystemTemp\jf0lifbf\CSC26790449CA934BF2BAA374F3C5EEFB42.TMP"
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RES3C71.tmp" "c:\Windows\SystemTemp\0q3d5pbl\CSC437AFE5AE1594DD597B24CACB6D48BA6.TMP"
   ```

Sysmon EID 1 records all of these process creation events with full hashes. `MSBuild.exe` SHA256 is `151D0125C20CDDE578D02DE3F2A56EB904870A887BB7F1C59BF61471DA231916`, IMPHASH `F34D5F2D4577ED6D9CEEC516C1F5A744`. `cmd.exe` SHA256 `A6E3B3B2...`, IMPHASH `139E6EEC...`.

Sysmon EID 11 records the output DLL written by `csc.exe`:
```
C:\Windows\SystemTemp\0q3d5pbl\0q3d5pbl.dll
```

This is the compiled inline task assembly — the actual compiled code product of the MSBuild inline task execution. This file is a definitive artifact that MSBuild executed code compilation, not just parsed a project file.

Sysmon EID 10 records PowerShell accessing `cmd.exe` twice with `GrantedAccess: 0x1FFFFF` (execution and cleanup phases).

The PowerShell channel (96 events) contains the ART test framework boilerplate. The cleanup block `try { Invoke-AtomicTest T1127.001 -TestNumbers 1 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}` is captured in EID 4104.

## What This Dataset Does Not Contain

The compiled assembly `0q3d5pbl.dll` is a temp file that MSBuild deletes after use in most configurations. No cleanup event for this file is captured. The intermediate `.TMP` files for `cvtres.exe` are similarly transient.

No network events are present. The `.csproj` file is locally staged at `C:\AtomicRedTeam\atomics\T1127.001\src\` and no remote download occurs.

No Security audit events for file creation within `C:\Windows\SystemTemp\` because Object Access auditing is not enabled.

Compared to the defended variant (60 Sysmon / 20 Security / 34 PowerShell), this dataset has fewer Sysmon events (50 vs. 60) and fewer Security events (9 vs. 20). In the defended variant, Defender generated additional process creation events during scanning of the `.csproj` file and compiled output. The undefended dataset has a larger PowerShell channel (96 vs. 34) for the same AMSI-absence reason seen across all these datasets.

## Assessment

This is an excellent dataset for MSBuild inline task bypass detection. The complete process chain from PowerShell through `cmd.exe` → `MSBuild.exe` → `csc.exe` → `cvtres.exe` is fully captured, along with the compiled output DLL file creation event. This four-level process chain, with `MSBuild.exe` as the pivot point that spawns compiler tools, is the definitive signature of inline task execution.

The random temp directory names (`jf0lifbf`, `0q3d5pbl`) generated by the .NET compiler infrastructure are worth noting: these change with each execution, so detection logic must pattern-match on the directory structure (`C:\Windows\SystemTemp\[random]\[random].dll`) rather than exact file names.

The two `csc.exe` invocations correspond to the two inline tasks defined in the `.csproj` file. Each MSBuild inline task compiles a separate assembly. In a real attack, you might see only one `csc.exe` spawning if the project file has a single malicious inline task.

## Detection Opportunities Present in This Data

**`MSBuild.exe` spawned by `cmd.exe` with a `.csproj` file argument.** Security EID 4688 and Sysmon EID 1 record this directly. `MSBuild.exe` invoked from `cmd.exe` (which was in turn spawned from PowerShell) with a project file path is the primary detection signal. In development environments MSBuild is typically invoked by IDEs or CI/CD pipelines, not from PowerShell-spawned cmd.exe.

**`csc.exe` spawned by `MSBuild.exe`.** Sysmon EID 1 records `MSBuild.exe` as the `ParentImage` for `csc.exe`. This specific parent-child relationship, with command lines referencing randomly-named temp directories under `C:\Windows\SystemTemp\`, indicates inline task compilation rather than standard project build.

**`cvtres.exe` spawned by `csc.exe`.** The full chain `MSBuild.exe` → `csc.exe` → `cvtres.exe` confirms actual compilation executed, not just MSBuild project file parsing.

**DLL file creation in `C:\Windows\SystemTemp\[random]\[random].dll` by `csc.exe`.** Sysmon EID 11 records `0q3d5pbl\0q3d5pbl.dll` creation. A DLL appearing in `C:\Windows\SystemTemp\` created by `csc.exe` with a random-looking name is a reliable indicator of inline task compilation.

**PowerShell spawning `cmd.exe` to invoke MSBuild.** The outer PowerShell → cmd.exe → MSBuild chain via EID 1 `ParentImage` tracking reveals the full attack origin and makes this distinguishable from legitimate MSBuild invocations.
