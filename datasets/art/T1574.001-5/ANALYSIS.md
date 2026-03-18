# T1574.001-5: DLL — DLL Side-Loading using the dotnet startup hook environment variable

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes a variant that abuses the .NET `DOTNET_STARTUP_HOOKS` environment variable. When this variable is set to a DLL path, the .NET runtime will load and execute the specified assembly before the target application's `Main()` method runs. This gives an attacker a mechanism to inject code into any .NET application launch by presetting the environment variable, causing their DLL to run within the context of the next .NET process.

This test sets `DOTNET_STARTUP_HOOKS` to point to a pre-built ART DLL (`preloader.dll`) and then launches a .NET application via `dotnet` to trigger the hook.

## What This Dataset Contains

The dataset captures 89 events across Sysmon (37), Security (10), and PowerShell (42) logs collected over approximately 6 seconds on ACME-WS02.

**The environment variable staging is recorded:**

Sysmon Event 1 shows the core attack command:
- `cmd.exe /c set DOTNET_STARTUP_HOOKS="C:\AtomicRedTeam\atomics\T1574.002\bin\preloader.dll" & dotnet -...`

Sysmon Event 13 (Registry Value Set) captures an environmental registry modification:
- `TargetObject: HKLM\System\CurrentControlSet\Services\W32Time\Config\Status\LastGoodSampleInfo` — this is a system background write by `svchost.exe` and is environmental noise unrelated to the attack.

Sysmon Event 7 (Image Loaded) captures the .NET runtime DLLs loaded by the PowerShell test framework process, including `clr.dll`, `clrjit.dll`, and `mscoreei.dll`. Defender DLLs (`MpOAV.dll`, `MpClient.dll`) are present.

Sysmon Event 10 (Process Access) shows `powershell.exe` accessing `whoami.exe` and `cmd.exe` — test framework subprocess management.

Security Event 4688 records `whoami.exe` and `cmd.exe` process creation. `cmd.exe` exits with `0x0`.

Security Event 4703 appears twice — token right adjustments during SYSTEM-context test framework execution.

## What This Dataset Does Not Contain (and Why)

**The preloader.dll startup hook did not execute.** Windows Defender's real-time protection blocked the DLL load. No Sysmon Event 7 entry for `preloader.dll` appears; no dotnet child process activity is visible.

**No dotnet.exe process creation in Sysmon Event 1.** The Sysmon include-mode filter does not capture `dotnet.exe` by default (it is not in the LOLBin/suspicious list), and Defender may have terminated the process before execution began.

**No .NET application startup telemetry.** If the hook had succeeded, you would expect to see the target .NET app loading, followed by `preloader.dll` appearing in Event 7. Neither occurred.

**No file drop.** The malicious DLL was pre-positioned in the ART atomics directory from the test setup phase; no file creation event for `preloader.dll` appears in this capture window.

**Sysmon Event 13 content is environmental background noise.** The W32Time registry write recorded here is a routine Windows time sync operation and is unrelated to the attack. It appears because the Sysmon registry monitoring policy captures all registry sets matching certain patterns.

## Assessment

This dataset documents the staging telemetry for a `DOTNET_STARTUP_HOOKS`-based DLL side-load attempt. The environment variable set command is captured in process command lines, which is the key detection artifact. The actual payload DLL never loaded due to Defender intervention. This pattern is increasingly common in adversary tradecraft targeting .NET-heavy enterprise environments and is worth training detections on the command-line staging behavior.

## Detection Opportunities Present in This Data

- **Sysmon Event 1 / Security Event 4688**: `cmd.exe` command line containing `DOTNET_STARTUP_HOOKS=` — setting this environment variable inline before a dotnet invocation is a strong attack indicator.
- **Sysmon Event 1**: `cmd.exe` setting environment variables and immediately launching a .NET application — the `set VAR=... & dotnet ...` pattern indicates hijack intent.
- **Sysmon Event 7**: `clr.dll` and `clrjit.dll` loaded by PowerShell during a short-lived execution window with no obvious .NET application invocation — unexpected CLR loads can indicate attempted hook exploitation.
- **Sysmon Event 10**: `powershell.exe` spawning `cmd.exe` with environment variable manipulation — PowerShell→cmd→dotnet process chain warrants scrutiny.
- **Security Event 4703**: Token right adjustment in SYSTEM context — capability changes during attack execution.
- **PowerShell Event 4103**: `Set-ExecutionPolicy -Scope Process -Force` — scripted execution context indicator.
