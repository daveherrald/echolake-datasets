# T1562.001-37: Disable or Modify Tools — WMIC Tamper with Windows Defender (Evade Scanning Folder)

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) covers actions that
weaken or circumvent security software. This test adds a path exclusion to Windows Defender
using the WMI Command-Line (WMIC) interface, writing to the `MSFT_MpPreference` WMI class.
Adding a folder exclusion means Defender will not scan files in that path, enabling an
adversary to stage malware, execute payloads, or store stolen data without triggering
real-time protection.

The WMI approach is an alternative to `Set-MpPreference` and may evade detection rules
focused only on PowerShell-based Defender configuration tampering. WMIC calls the underlying
WMI provider that also backs `Set-MpPreference`, producing the same effect through a
different execution path.

In this **undefended** dataset, Defender is disabled at the policy level. The WMIC call
completes with exit status `0x0`.

## What This Dataset Contains

The dataset captures 102 events across two channels (97 PowerShell, 5 Security) spanning
approximately 4 seconds on ACME-WS06 (Windows 11 Enterprise Evaluation, 2026-03-17).

**Security EID 4688 — Five process creation events capturing the full execution chain:**

1. `"C:\Windows\system32\whoami.exe"` (pre-execution ART identity check)
2. `"cmd.exe" /c wmic.exe /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath="ATOMICREDTEAM"` (cmd.exe with the full WMIC command)
3. `wmic.exe  /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath="ATOMICREDTEAM"` (wmic.exe as child of cmd.exe)
4. `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpCmdRun.exe" GetDeviceTicket -AccessKey B42DD009-14C8-7704-73F1-FE8509F44CC8` (Defender response to the WMI exclusion call)
5. `"C:\Windows\system32\whoami.exe"` (post-execution ART identity check)

Event 4 is particularly significant: `MpCmdRun.exe` is the Defender management command-line
tool, and the `GetDeviceTicket` call with an access key appears to be Defender's WMI
provider handler responding to the `MSFT_MpPreference` modification. This event shows that
the Defender engine actively processed the exclusion request, even on a host where the
engine is running with real-time protection disabled.

The double-space in `wmic.exe  /Namespace:...` is the characteristic cmd.exe argument
passing artifact.

**PowerShell EID 4104 — 96 script block events.** The ART test framework boilerplate is present.
No PowerShell-specific content for the WMIC exclusion call appears in 4104 because the
operation was routed through `cmd.exe`, not a PowerShell cmdlet.

**PowerShell EID 4103 — One module pipeline event** for the `Set-ExecutionPolicy` test framework
call.

**No EID 4100 error events.** All processes exited cleanly (`0x0`). The WMIC call succeeded
at the OS level.

## What This Dataset Does Not Contain

**Confirmation that the exclusion was committed to Defender's configuration.** All process
exits with `0x0` indicate the WMIC call completed without error, but no Sysmon EID 13
(registry value set) or WMI subscription event confirms the exclusion was written to
Defender's exclusion list. In the defended variant, `MsMpEng.exe` made outbound connections
to `48.211.71.197:443` immediately after the exclusion attempt — consistent with Defender
telemetry uploading the event. Those network connections do not appear in this undefended
dataset.

**Sysmon events.** Sysmon data is not bundled. The defended variant includes only Sysmon
EID 3 (two `MsMpEng.exe` network connections to `48.211.71.197:443`) and no EID 1, because
neither `cmd.exe` nor `wmic.exe` matched the sysmon-modular ProcessCreate include rules for
this specific execution path in the defended test. The undefended dataset has no Sysmon
channel at all.

**WMI subscription or class modification events.** Windows Security event ID 4662 or 5857
(WMI activity) do not appear in the Security channel. WMI provider method invocations do
not automatically generate Security audit events in this configuration.

**Any Defender blocks or AMSI events.** With Defender disabled, no AMSI block, script
content detection, or behavior monitoring alert appears for the WMIC call.

## Assessment

This dataset demonstrates a successful WMIC-based Defender exclusion addition. The
execution chain is cleanly captured in Security 4688: `cmd.exe` carrying the full WMIC
namespace and class invocation, followed by `wmic.exe` with the exact arguments, and then
`MpCmdRun.exe GetDeviceTicket` as Defender's internal response to processing the WMI
method call.

The `MpCmdRun.exe GetDeviceTicket -AccessKey B42DD009-14C8-7704-73F1-FE8509F44CC8` event
(Security 4688, event 4) is not typically associated with the defended dataset's telemetry
for this test and likely reflects the Defender engine's WMI provider handler issuing a
device ticket for the exclusion configuration change. This process create would appear in
any environment where the WMIC call successfully reaches the `MSFT_MpPreference` class and
Defender processes it — making it a potential indicator of WMI-based Defender tampering
even when the modification is not otherwise logged.

## Detection Opportunities Present in This Data

**Security EID 4688 — `wmic.exe` with `/Namespace:\\root\Microsoft\Windows\Defender` and
`class MSFT_MpPreference call Add ExclusionPath`.** The full WMIC command is captured in
two 4688 events: once as the `cmd.exe` command line and once as the `wmic.exe` command
line. Both are high-confidence indicators. The namespace `\\root\Microsoft\Windows\Defender`
combined with a `call Add` method on `MSFT_MpPreference` and an `ExclusionPath` argument
is a highly specific pattern.

**Security EID 4688 — `MpCmdRun.exe GetDeviceTicket`.** The Defender management tool
appearing with `GetDeviceTicket -AccessKey` arguments is not a routine Defender operation
and may be logged whenever the `MSFT_MpPreference` WMI class is modified. This event can
serve as a secondary indicator that the Defender WMI provider successfully processed a
preference change.

**Security EID 4688 — `cmd.exe` spawning `wmic.exe` with Defender WMI namespace.** The
cmd.exe to wmic.exe process chain with the Defender namespace is distinct from legitimate
Defender administration, which typically uses `Set-MpPreference` or the Defender portal.

**PowerShell → cmd.exe → wmic.exe chain as SYSTEM.** The three-level chain running as
`NT AUTHORITY\SYSTEM` to perform a WMI-based Defender configuration change is not a normal
administrative pattern. Legitimate Defender exclusion management in enterprise environments
is typically performed via Group Policy or Intune.
