# T1529-1: System Shutdown/Reboot — Windows

## Technique Context

T1529 (System Shutdown/Reboot) describes adversary-initiated system shutdowns or reboots as an impact technique. Attackers use forced shutdowns to interrupt operations, prevent incident response, end monitoring processes, complete destructive operations before recovery, or trigger boot-time persistence mechanisms. On Windows, the canonical tools are `shutdown.exe` (with `/s` for shutdown or `/r` for restart) and the Win32 `ExitWindowsEx` API. The technique is also accessible via PowerShell (`Stop-Computer`, `Restart-Computer`) and WMI (`Win32_OperatingSystem.Win32Shutdown`). Detection typically targets `shutdown.exe` invocation outside of maintenance windows, shutdown API calls from unexpected processes, and System event log ID 1074 (which records the initiating process and reason code).

## What This Dataset Contains

This dataset captures a test where the ART test framework attempted to execute the shutdown test but encountered an execution error. The PowerShell 4103 module logging event records:

```
CommandInvocation(Invoke-AtomicTest): "Invoke-AtomicTest"
ParameterBinding(Invoke-AtomicTest): name="TestNumbers"; value="1"
TerminatingError(Invoke-AtomicTest): "Cannot convert 'System.String' to the type
'System.Management.Automation.SwitchParameter' required by parameter 'Confirm'."
```

The same `TerminatingError` appears for both the execution and cleanup invocations. The Sysmon channel contains 44 events, all of which are event ID 7 (Image Loaded) and event ID 11 (File Created) and event ID 17 (Pipe Created) associated with multiple PowerShell instances starting up and loading their DLL dependencies — there are no Sysmon event ID 1 (Process Create) entries for any shutdown-related executable.

The Security channel records 12 events, all event ID 4689 (Process Exited), covering PowerShell and conhost exits, plus WmiPrvSE and WmiApSrv exits — consistent with the WMI-based execution infrastructure used by the guest agent. Two PowerShell instances exit with status `0x1` (error), which corresponds to the `TerminatingError` logged in the PowerShell channel.

## What This Dataset Does Not Contain

No `shutdown.exe` process creation appears in any channel. The technique did not execute because the ART Invoke-AtomicTest call failed with a parameter binding error. No Security 4688 or Sysmon event ID 1 for `shutdown.exe` is present.

There are no System log events (event ID 1074 — the "The process initiated a shutdown" event) because the shutdown was never invoked.

No Security 4688 events are present at all — the collection window captured only process exits, not the initial process creations for the test framework PowerShell instances.

The PowerShell channel is exclusively boilerplate: `Set-ExecutionPolicy`, `Set-StrictMode` error-handler fragments, and `Invoke-AtomicTest` failure logging. The 91 events provide no technique-relevant content beyond confirming the test framework ran and failed.

## Assessment

This dataset does not contain technique execution telemetry. The test did not run due to an ART test framework parameter binding incompatibility. From a detection engineering standpoint, this dataset is useful primarily as an example of what failure telemetry looks like — PowerShell exit with code `0x1`, `TerminatingError` in 4103, and no downstream process activity. It may be useful for testing detection rules that fire on *absence* of expected cleanup activity (e.g., alerting when `Invoke-AtomicTest` is logged but no expected child process follows), but it does not provide positive examples of `shutdown.exe` or shutdown API usage. Compare with T1529-2, which successfully executed `shutdown /r /t 1` and contains the corresponding System event ID 1074.

## Detection Opportunities Present in This Data

1. **PowerShell 4103 TerminatingError on Invoke-AtomicTest** — The module logging records the test framework invocation and its failure, which is useful as a test-execution audit trail but not a T1529 detection signal.
2. **Multiple PowerShell instances with exit code 0x1** — Two Security 4689 events with `Exit Status: 0x1` indicate failed script executions; pairing these with 4103 TerminatingError events enables reconstruction of what failed.
3. **WmiPrvSE and WmiApSrv process exits** — The WMI infrastructure exiting after PowerShell failures is consistent with the QEMU guest agent's WMI-based execution model and useful for understanding test framework process chain, but is not a detection opportunity for T1529 itself.
