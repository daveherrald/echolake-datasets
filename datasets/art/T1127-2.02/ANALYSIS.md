# T1127-2: Trusted Developer Utilities Proxy Execution — Lolbin jsc.exe Compile JavaScript to DLL

## Technique Context

T1127 Trusted Developer Utilities Proxy Execution describes adversaries abusing legitimate developer tools — tools that are trusted by the operating system, whitelisted by application control policies, or simply overlooked by defenders — to execute malicious code. These tools are often signed by Microsoft and ship with the .NET Framework or Visual Studio, making them difficult to block without impacting developer workflows.

This test targets `jsc.exe`, the JavaScript compiler that ships with the .NET Framework v4. `jsc.exe` takes a JavaScript source file as input and compiles it to a .NET assembly (DLL or EXE). Because it is a Microsoft-signed binary that performs legitimate compilation, it is frequently trusted by application whitelisting policies that allow .NET Framework executables.

The attack chain:
1. Copy `LibHello.js` (a benign JavaScript source file from the ART atomics directory) to `%TEMP%\LibHello.js`
2. Invoke `C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe /t:library %TEMP%\LibHello.js` to compile it to a DLL
3. Cleanup: delete the `.js` and `.dll` files from `%TEMP%`

In a real attack, the JavaScript file would contain malicious code that, once compiled and loaded, provides execution capability under a trusted Microsoft binary's authority.

The wrapper command used is:
```
cmd.exe /c copy "C:\AtomicRedTeam\atomics\T1127\src\LibHello.js" %TEMP%\LibHello.js & C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe /t:library %TEMP%\LibHello.js
```

## What This Dataset Contains

The dataset captures 26 Sysmon events, 6 Security events, and 107 PowerShell events recorded on ACME-WS06 with Windows Defender fully disabled.

The technique execution is clearly documented in both Security and Sysmon channels. Security EID 4688 records the full process chain:

1. `powershell.exe` spawns `cmd.exe` with the copy-and-compile command:
   ```
   "cmd.exe" /c copy "C:\AtomicRedTeam\atomics\T1127\src\LibHello.js" %TEMP%\LibHello.js & C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe /t:library %TEMP%\LibHello.js
   ```

2. `cmd.exe` spawns `jsc.exe`:
   ```
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\jsc.exe  /t:library C:\Windows\TEMP\LibHello.js
   ```

3. `jsc.exe` spawns `cvtres.exe` as part of the compilation:
   ```
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RES9F8.tmp" "C:\Windows\SystemTemp\RES9E8.tmp"
   ```

4. Cleanup: `cmd.exe /c del %TEMP%\LibHello.js & del %TEMP%\LibHello.dll`

Sysmon EID 1 records all four process creation events with full SHA256 hashes:
- `cmd.exe`: SHA256 `A6E3B3B2...`, IMPHASH `139E6EEC...`
- `jsc.exe`: not directly sampled in EID 1 but visible in EID 4688
- `whoami.exe`: SHA256 `574BC2A2...`, IMPHASH `62935820...`

Sysmon EID 10 records PowerShell accessing `cmd.exe` with `GrantedAccess: 0x1FFFFF` (both the execution and cleanup cmd.exe invocations).

Sysmon EID 11 records `C:\Windows\Temp\LibHello.js` being created by `cmd.exe` — this is the file copy step, visible as a file creation event before `jsc.exe` begins compilation.

The PowerShell channel (107 events, EID 4104) consists of ART test framework boilerplate. No script block captures the `jsc.exe` invocation specifically because it is run via `cmd.exe` as a subprocess argument.

## What This Dataset Does Not Contain

This dataset does not contain the compiled output DLL. While `jsc.exe` would have written `LibHello.dll` to `%TEMP%`, no Sysmon EID 11 event capturing that specific file creation is included in this sample. Researchers should query the full dataset files for `C:\Windows\Temp\LibHello.dll` or `LibHello.dll` file creation events.

The cleanup command (`del %TEMP%\LibHello.js & del %TEMP%\LibHello.dll`) does not generate Sysmon EID 23 (File Deletion) events because the Sysmon configuration on this host does not enable file deletion monitoring.

No `jsc.exe`-specific image loads are captured in the Sysmon EID 7 sample — those events would reflect `jsc.exe` loading .NET assemblies, which would be distinct from the `powershell.exe` image loads that dominate the EID 7 sample.

Compared to the defended variant (24 Sysmon / 14 Security / 34 PowerShell), this dataset has slightly more Sysmon events (26 vs. 24) and fewer Security events (6 vs. 14). The defended execution's higher Security count reflects Defender process creation events during scanning. The Sysmon counts are similar because the process chain is identical — Defender presence/absence does not significantly change the number of process, file, or pipe events for this technique.

## Assessment

This is a high-quality dataset for the `jsc.exe` lolbin abuse pattern. The entire process chain — PowerShell → cmd.exe → jsc.exe → cvtres.exe — is captured with full command lines in both Security EID 4688 and Sysmon EID 1. The `cvtres.exe` spawning by `jsc.exe` is particularly notable: `cvtres.exe` (the COFF/PE resource compiler) is a secondary indicator that code compilation actually occurred, not just a `jsc.exe` invocation that was blocked or failed.

The dataset correctly represents the full execution lifecycle including cleanup. Detection engineers can use this to build a complete attack chain model: file drop (EID 11 for `LibHello.js`), compilation (process chain via EID 1/4688), resource compilation (cvtres.exe), and cleanup (cmd.exe with `del`).

## Detection Opportunities Present in This Data

**`jsc.exe` spawned by `cmd.exe` with `/t:library` flag.** Security EID 4688 and Sysmon EID 1 record this directly. `jsc.exe` is rarely executed outside of .NET developer contexts; seeing it spawn from `cmd.exe` which itself was spawned from `powershell.exe` is high-fidelity for lolbin abuse.

**`cvtres.exe` spawned by `jsc.exe`.** Sysmon EID 1 records `jsc.exe` as the `ParentImage` for `cvtres.exe`. `cvtres.exe` is a secondary indicator that actual compilation occurred. This parent-child relationship is unusual in non-developer environments.

**PowerShell spawning `cmd.exe` with a file copy combined with developer tool invocation.** The command string `copy ... & jsc.exe /t:library` in a PowerShell-spawned `cmd.exe` is characteristic of automated lolbin chaining. Legitimate developer workflows use MSBuild projects or IDE toolchains, not ad-hoc `cmd.exe` copy-and-compile chains.

**File creation at `%TEMP%\LibHello.js`.** Sysmon EID 11 records `cmd.exe` creating `C:\Windows\Temp\LibHello.js`. Unexpected JavaScript files appearing in `%TEMP%` as a precursor to `jsc.exe` execution is a staged-file-then-compile pattern worth monitoring.
