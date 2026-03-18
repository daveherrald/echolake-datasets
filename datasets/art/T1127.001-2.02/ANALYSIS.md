# T1127.001-2: MSBuild — MSBuild Bypass Using Inline Tasks (VB)

## Technique Context

T1127.001 MSBuild describes the abuse of `MSBuild.exe` to execute arbitrary code embedded in XML project files as "inline tasks." While T1127.001-1 covers the C# variant, this test uses Visual Basic .NET — a different compiler toolchain that produces the same outcome through `vbc.exe` (the VB compiler) rather than `csc.exe`.

The distinction matters for detection: defenders tuned to watch for `csc.exe` spawned by `MSBuild.exe` will not catch this VB variant. Both compilers are legitimate Microsoft-signed .NET Framework binaries, but they are separate tools with distinct paths and hashes. Real-world attackers choose between C# and VB inline tasks based on defender tuning and operational preference.

The executed command:
```
cmd.exe /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\vb.xml"
```

The project file is `vb.xml` rather than `.csproj`, which is also notable — MSBuild processes any XML file with the correct schema, not just files with standard extensions. This can further evade detections that only alert on `.csproj` or `.targets` files passed to MSBuild.

## What This Dataset Contains

The dataset captures 41 Sysmon events, 8 Security events, 107 PowerShell events, and 6 Task Scheduler events recorded on ACME-WS06 with Windows Defender fully disabled.

The VB compilation chain is fully documented in Security EID 4688:

1. PowerShell spawns `cmd.exe`:
   ```
   "cmd.exe" /c C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe "C:\AtomicRedTeam\atomics\T1127.001\src\vb.xml"
   ```

2. `cmd.exe` spawns `MSBuild.exe`:
   ```
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe  "C:\AtomicRedTeam\atomics\T1127.001\src\vb.xml"
   ```

3. `MSBuild.exe` spawns `vbc.exe` (Visual Basic compiler):
   ```
   "C:\Windows\Microsoft.NET\Framework\v4.0.30319\vbc.exe" /noconfig @"C:\Windows\SystemTemp\xikq2fr0\xikq2fr0.cmdline"
   ```

4. `vbc.exe` spawns `cvtres.exe`:
   ```
   C:\Windows\Microsoft.NET\Framework\v4.0.30319\cvtres.exe /NOLOGO /READONLY /MACHINE:IX86 "/OUT:C:\Windows\SystemTemp\RES60F1.tmp" "C:\Windows\SystemTemp\vbc85D96FBE852E4B3A9C9D234DACC2251.TMP"
   ```

Sysmon EID 1 records the same chain. `MSBuild.exe` SHA256 `151D0125...`, IMPHASH `F34D5F2D...` — identical to the C# test, confirming this is the same MSBuild binary. `cmd.exe` SHA256 `A6E3B3B2...`.

The `vbc.exe` temp directory name (`xikq2fr0`) and the `cvtres.exe` temp file prefix (`vbc85D96FBE852E4B3A9C9D234DACC2251.TMP`) are visibly different from the C# variants — `csc.exe` prefixes temp files with `CSC`, while `vbc.exe` uses `vbc`. This is a compiler-specific artifact useful for distinguishing C# vs. VB inline tasks in forensic analysis.

The Security channel also includes an interesting unrelated event (EID 4688) recording:
```
"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /ua /installsource scheduler
```
spawned by `svchost.exe -k netsvcs -p -s Schedule`. This is a scheduled Windows Update for Microsoft Edge that coincidentally fired during the test window. It is authentic background activity, not a technique artifact.

The Task Scheduler channel (6 events: EIDs 107, 129, 100, 200, 201, 102) records the Edge Update task lifecycle — trigger, launch, start, action, action complete, and finish. These events are entirely unrelated to the MSBuild technique and represent normal Windows background activity occurring concurrently with the test.

Sysmon EID 7 captures `C:\Windows\SysWOW64\taskschd.dll` loaded into `MicrosoftEdgeUpdate.exe` — again, the scheduler DLL loaded by the Edge updater, not related to MSBuild.

The PowerShell channel (107 events, EID 4104) is standard ART test framework boilerplate.

## What This Dataset Does Not Contain

Unlike the C# test (T1127.001-1), there is no Sysmon EID 11 capturing the VB compiler's output DLL in this sample set. The VB task likely produced an output assembly in `C:\Windows\SystemTemp\xikq2fr0\`, but that file creation event was not included in the 20-event Sysmon sample. Researchers should query the full dataset for VB compiler output.

No network events are present. The `vb.xml` project file is locally staged.

The Task Scheduler and Edge Update events are genuinely present in the raw data but are coincidental background activity. They are preserved in the dataset as authentic environmental context.

Compared to the defended variant (46 Sysmon / 18 Security / 34 PowerShell), this dataset is smaller in Sysmon (41 vs. 46) and Security (8 vs. 18). The defended variant had more events partly because Defender generated additional process creation and scan-related events when MSBuild compiled code. The undefended dataset again has a larger PowerShell channel (107 vs. 34).

## Assessment

This dataset complements T1127.001-1 by providing the VB compiler variant of the same technique. The process chain is structurally identical to the C# test but uses different tools (`vbc.exe` instead of `csc.exe`). Detection logic that covers both variants must account for both compiler tools as potential MSBuild children.

The presence of the Edge Update scheduled task activity in this dataset is representative of the real-world challenge: a production host running this test would have background Windows maintenance tasks active, and detection analytics must not alert on the Edge Update process chain while correctly flagging the MSBuild chain. The dataset provides both signals simultaneously, making it useful for testing detection precision.

The `.xml` extension for the project file (instead of `.csproj`) is also a subtle evasion indicator: content-based detection that looks at file structure rather than extension would catch both; extension-based filtering would miss this.

## Detection Opportunities Present in This Data

**`MSBuild.exe` with `vb.xml` as argument.** Security EID 4688 and Sysmon EID 1 record `msbuild.exe` with a non-standard extension project file. Any MSBuild invocation with `.xml` (rather than `.csproj`, `.targets`, or `.props`) warrants attention.

**`vbc.exe` spawned by `MSBuild.exe`.** Sysmon EID 1 records this specific parent-child relationship. `vbc.exe` spawned from `MSBuild.exe` in a non-development context indicates inline VB task compilation.

**`cvtres.exe` spawned by `vbc.exe`.** The full chain `MSBuild.exe` → `vbc.exe` → `cvtres.exe` is the VB equivalent of the C# chain's `MSBuild.exe` → `csc.exe` → `cvtres.exe`. Both terminate at `cvtres.exe`, which is the universal indicator that code compilation completed.

**Temp file prefix `vbc` in `C:\Windows\SystemTemp\`.** The `cvtres.exe` command line references `vbc85D96FBE852E4B3A9C9D234DACC2251.TMP` — the `vbc` prefix distinguishes this from C# compiler temp files. Security auditing or file monitoring on `C:\Windows\SystemTemp\` would surface both compiler variants.

**Concurrent legitimate scheduled task activity.** The Edge Update events (EIDs 100/102 in Task Scheduler channel) demonstrate that background maintenance activity can run concurrently with attack execution. Analytics developers should ensure this activity does not produce false positives when MSBuild activity is also present.
