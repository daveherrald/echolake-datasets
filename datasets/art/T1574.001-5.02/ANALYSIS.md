# T1574.001-5: DLL Search Order Hijacking — DLL Side-Loading using the dotnet startup hook environment variable

## Technique Context

T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking) includes a variant that abuses the .NET runtime's `DOTNET_STARTUP_HOOKS` environment variable. When this variable is set to a DLL path, the .NET Common Language Runtime (CLR) loads and executes the specified assembly **before** any managed code in the target process runs — including before `Main()`. This gives an attacker a mechanism to inject code into any .NET process launch by simply presetting the environment variable in a parent process or system configuration.

This test sets `DOTNET_STARTUP_HOOKS` to point to a pre-built ART payload DLL (`C:\AtomicRedTeam\atomics\T1574.002\bin\preloader.dll`) within a `cmd.exe` environment variable scope, then runs `dotnet -h` to trigger the hook. A `taskkill /F /IM calculator.exe` cleanup action follows, implying the payload launches a calculator as its indicator of successful execution.

## What This Dataset Contains

The dataset captures 122 events across two log sources: PowerShell (107 events: 104 EID 4104, 3 EID 4103) and Security (15 events: 9 EID 4689, 5 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The attack execution is fully visible in Security EID 4688.** PowerShell spawned cmd.exe with:

```
"cmd.exe" /c set DOTNET_STARTUP_HOOKS="C:\AtomicRedTeam\atomics\T1574.002\bin\preloader.dll"
          & dotnet -h > nul
          & echo.
```

This single command line sets the startup hook environment variable and immediately invokes `dotnet` — the .NET CLI tool — within the same `cmd.exe` session. The CLR will load `preloader.dll` before executing the `dotnet -h` help routine.

The cleanup step is also captured:

```
"cmd.exe" /c taskkill /F /IM calculator.exe >nul 2>&1
```

Which spawned:

```
taskkill /F /IM calculator.exe
Creator Process Name: C:\Windows\System32\cmd.exe
```

The `taskkill` targeting `calculator.exe` confirms the payload ran. All five EID 4688 process creation events exited at `0x0`.

Security EID 4703 records PowerShell (PID 0x4368) receiving elevated privileges including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeTakeOwnershipPrivilege` — consistent with SYSTEM-context execution.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 1 (with image hash), EID 7 (Image Loaded — which would show `preloader.dll` being loaded into the `dotnet` process), or EID 11 (File Created), you cannot observe the DLL injection mechanism directly. The startup hook took effect within the `cmd.exe` session's environment scope, so no child process was spawned solely to set the variable — it was all in one command chain.

**No `dotnet.exe` process creation event.** Because `dotnet` was launched by cmd.exe within the same shell that set the environment variable, the Security log does show the cmd.exe creation but `dotnet.exe` itself may not have generated a separate EID 4688 record in the captured sample set (cmd.exe ran it as a child, but it is not in the collected samples).

**No file write events.** The `preloader.dll` was pre-positioned before the test window.

**No network activity.** This payload spawns a calculator; no network connections are expected.

## Assessment

The defended variant recorded 37 Sysmon, 10 Security, and 42 PowerShell events. In that run, Defender intercepted the payload DLL before or during load. In this undefended run, `preloader.dll` loads successfully, the calculator is spawned, and the subsequent `taskkill` cleanup confirms end-to-end success.

The key forensic artifact in this dataset is the `DOTNET_STARTUP_HOOKS` environment variable assignment visible in the EID 4688 command line. This is the precise mechanism of the attack — the variable scoped to the cmd.exe process — and it is captured in full. The absence of Sysmon means you do not see the DLL load itself, but the combination of the startup hook assignment and the calculator cleanup strongly implies the hook executed.

## Detection Opportunities Present in This Data

**EID 4688 — cmd.exe command line containing `DOTNET_STARTUP_HOOKS`.** Setting `DOTNET_STARTUP_HOOKS` in a scripted context to point to an arbitrary DLL path is an extremely high-fidelity indicator. Legitimate .NET tooling does not set this variable to paths under `C:\AtomicRedTeam\` or any non-vendor directory. The variable itself should be rare in Security EID 4688 command lines.

**EID 4688 — taskkill /F /IM calculator.exe following dotnet execution.** This cleanup sequence is a reliable artifact of ART-style startup hook tests. In a real attack, the payload would differ, but the same pattern of DLL-triggered process followed by cleanup applies.

**EID 4688 — PowerShell (SYSTEM) → cmd.exe → dotnet with environment variable injection.** The combination of SYSTEM-context PowerShell spawning a cmd.exe that both sets a sensitive environment variable and immediately invokes a .NET process is an anomalous execution pattern worth investigating.

**Environment variable scope analysis.** Because `DOTNET_STARTUP_HOOKS` was set at the cmd.exe session level (not system-wide), it does not persist in the registry. Detection must rely on the process command line itself, which this dataset provides.
