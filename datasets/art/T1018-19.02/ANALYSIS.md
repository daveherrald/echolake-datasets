# T1018-19: Remote System Discovery — Get-DomainController with PowerView

## Technique Context

T1018 Remote System Discovery encompasses any method by which adversaries map out systems in their target environment. The PowerView variant uses `Get-DomainController`, a function from the PowerSploit PowerView module, to query Active Directory for domain controller objects. PowerView is a comprehensive AD reconnaissance library that wraps ADSI and .NET directory services calls into a PowerShell interface, making AD enumeration accessible without external binaries. Attackers value it because it runs entirely in memory, requires no disk writes for the module itself (when loaded via IEX from a URL), and can be chained with other PowerView functions to build a complete picture of the domain topology.

Detection engineers focus on three indicators for this technique variant: network retrieval of PowerView from GitHub or an attacker-controlled host, the specific `Get-DomainController` function name appearing in PowerShell script block logs, and LDAP queries to domain controllers from unusual source processes. The script block logging approach is particularly important because even when PowerView is loaded from a URL with no file on disk, EID 4104 will capture the module code as it is compiled into a script block.

In the defended version of this test, Windows Defender blocked the technique at the `STATUS_ACCESS_DENIED` (0xC0000022) exit code level, and PowerShell script block logging contained no PowerView content. With Defender disabled, the path is unobstructed.

## What This Dataset Contains

The dataset covers roughly 5 seconds (22:58:35–22:58:41 UTC on 2026-03-14) and contains 359 events across five channels. The Sysmon channel (22 events) provides the richest technique telemetry.

PowerShell (PID 6232) is the driver process. Sysmon EID 1 records `whoami.exe` executing twice as pre- and post-check processes spawned by the ART test framework. The technique process creates show a child PowerShell spawned to execute the PowerView command. A critically notable event is Sysmon EID 8 (CreateRemoteThread): PowerShell (PID 6232) creates a thread in an `<unknown process>` (PID 6340) with start address `0x00007FF77E8753A0`. This is the network fetch for PowerView — an IWR (Invoke-WebRequest) call to `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1`. The target process has already exited by the time Sysmon logs it, which is why it appears as `<unknown process>`.

Sysmon EID 13 captures two registry writes: `HKCR\WdMam\Shell\Open\Command\(Default)` set by `SecurityHealthService.exe` to a value pointing to `SecurityHealthHost.exe`, and two service security descriptor writes to `HKLM\System\CurrentControlSet\Services\SecurityHealthService\Security\Security` and `HKLM\System\CurrentControlSet\Services\wscsvc\Security\Security` by `services.exe`. These reflect Windows Security Center updating its state in response to Defender being disabled.

Sysmon EID 7 shows PowerShell loading `urlmon.dll` (OLE32 Extensions, used by Invoke-WebRequest for HTTP operations). The Security channel's 6 EID 4688 events and the 226 EID 4664 hard-link events are a mix of process creation records and OS servicing activity.

The key distinction from the defended dataset: in the defended run, the PowerShell process exited with `0xC0000022` and no PowerView content appeared in script block logging. Here, execution proceeds. The SecurityHealthService activity (Sysmon EID 13) and `<unknown process>` thread creation event are both artifacts of running in an environment where Defender is disabled but Security Center is still reconciling service state — these would not appear in a truly clean test environment.

## What This Dataset Does Not Contain

The PowerShell channel contains only test framework boilerplate in EID 4104 — no PowerView module code, no `Get-DomainController` call, no results. This is the most significant gap: despite execution proceeding further than in the defended version, the actual PowerView source was apparently not successfully retrieved or executed. The network connection to GitHub (raw.githubusercontent.com) is not captured in a Sysmon EID 3 event. There are no LDAP queries to domain controllers, no DNS resolution events for AD infrastructure, and no file creation of any output. The Security channel's EID 4688 sample set is fully consumed by the 226 EID 4664 hard-link events in the 20-event sample, so process command line details from Security are not in the provided samples (though the events exist in the full dataset).

## Assessment

This dataset is partially complete for the PowerView technique. It provides process creation evidence (Sysmon EID 1 for the PowerShell child process spawned to run the technique) and shows the broader execution environment including the urlmon.dll load indicating a web request was attempted. However, the absence of PowerShell script block content capturing PowerView code means the primary detection artifact for this technique is missing. The Sysmon EID 8 CreateRemoteThread event is an unusual and high-value data point that warrants investigation as a detection indicator in its own right. The Security Center registry writes in EID 13 are useful as environmental context for datasets from Defender-disabled systems.

## Detection Opportunities Present in This Data

1. **Sysmon EID 7 — urlmon.dll load in PowerShell**: `urlmon.dll` being loaded into `powershell.exe` is expected for `Invoke-WebRequest` calls. Combined with a subsequent child PowerShell spawn within milliseconds, this pattern indicates a download-and-execute workflow.

2. **Sysmon EID 8 — CreateRemoteThread from PowerShell**: PowerShell creating a remote thread in another process, particularly when the target is an `<unknown process>` (already exited by log time), is an anomalous behavior that warrants investigation regardless of the downstream technique.

3. **Sysmon EID 1 — PowerShell spawning PowerShell with IEX**: In the full dataset, the child PowerShell command line contains `IEX (IWR '...' -UseBasicParsing)` pattern. This download-cradle command line is a high-priority detection target for PowerShell-based fileless attacks.

4. **EID 4104 — Get-DomainController in script blocks**: If PowerView executes successfully, EID 4104 will contain the module source code and the `Get-DomainController` function call. Pattern matching on `Get-DomainController`, `PowerSploit`, or the PowerView GitHub URL in script block text is the primary detection path.

5. **Sysmon EID 13 — Security Center registry modifications**: `HKCR\WdMam\Shell\Open\Command\(Default)` being set by `SecurityHealthService.exe` is a reliable indicator that Windows Defender real-time protection has been disabled. This registry path can serve as an environmental detection for the attacker having tampered with endpoint defenses.
