# T1033-5: System Owner/User Discovery — GetCurrent User with PowerShell Script

## Technique Context

T1033 System Owner/User Discovery is a fundamental Discovery technique where adversaries identify the current user context of their execution environment. Understanding which account is running their code helps attackers assess their privilege level, decide whether to escalate, and tailor subsequent actions to the account's capabilities. This test demonstrates using PowerShell's `[System.Security.Principal.WindowsIdentity]::GetCurrent()` .NET API call — a technique that reaches directly into the Windows security token infrastructure without spawning external processes like `whoami.exe`.

The `WindowsIdentity.GetCurrent()` method returns a rich security context object containing the username, SID, authentication type, impersonation level, and group memberships. Because it is a pure in-process API call, it produces no child process creation events and is harder to detect at the process level than CLI-based enumeration. The output is written to a file (`CurrentUserObject.txt`) and then cleaned up. This pattern of writing discovery output to disk before collection and cleanup is characteristic of both automated toolkits and hands-on adversary operators.

Detection primarily relies on PowerShell script block logging (EID 4104) capturing the `WindowsIdentity` API call, and Security 4688 recording the child PowerShell process spawned with the full command line. Without script block logging enabled, this technique would generate minimal telemetry compared to `whoami.exe`-based discovery.

## What This Dataset Contains

This dataset spans approximately 15 seconds (2026-03-14T23:05:14Z–23:05:22Z, estimated from Sysmon timestamps) and contains 130 events: 97 PowerShell events, 4 Security events, 28 Sysmon events, and 1 Application event.

The Security channel (EID 4688) is the primary evidence source. It records the main attack command: `"powershell.exe" & {[System.Security.Principal.WindowsIdentity]::GetCurrent() | Out-File -FilePath .\CurrentUserObject.txt}`, clearly showing the API invocation and file write. A second EID 4688 captures the cleanup: `"powershell.exe" & {Remove-Item -Path .\CurrentUserObject.txt -Force}`. Two additional `whoami.exe` spawns appear as part of the test framework verification logic.

Sysmon EID 1 confirms process creation of both the main PowerShell invocation and the whoami check, with the main execution tagged `RuleName: technique_id=T1059.001`. EID 10 (process access) shows `powershell.exe` accessing both `whoami.exe` and itself — the self-access pattern appears consistently across these ART PowerShell tests as a .NET interop artifact. EID 7 image loads include the .NET runtime chain (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `clrjit.dll`, `mscorlib.ni.dll`) along with `urlmon.dll`, reflecting the network-capable PowerShell initialization. Two EID 17 named pipe events bookend the test execution.

Compared to the defended dataset (37 Sysmon, 10 Security, 38 PowerShell), the undefended version has slightly fewer events overall — this is expected because Defender's behavior monitoring was generating additional telemetry in the defended case through its own process introspection. The core execution telemetry is similar in both cases, which makes sense: `WindowsIdentity::GetCurrent()` is a benign .NET API that Defender would not block regardless.

The Application channel contains one EID 15 event: "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON" — this is an incidental notification from the GPO-based Defender disablement state and is not technique-related.

## What This Dataset Does Not Contain

No file system events (Sysmon EID 11) capture the creation of `CurrentUserObject.txt`, meaning the output file write is visible in the command line but not as a discrete file creation event in this dataset. The Sysmon configuration's file creation filtering likely excludes `.txt` files in the current working directory.

The PowerShell channel does not include script blocks showing the `[System.Security.Principal.WindowsIdentity]::GetCurrent()` call itself in the sampled events — the bulk of the 96 EID 4104 events contain PowerShell runtime internals and ART framework boilerplate. The actual API invocation would appear in the full dataset's script blocks but is not surfaced in samples.

No registry access events, LDAP queries, or network connections appear — consistent with the purely local, in-process nature of this technique variant.

## Assessment

This dataset demonstrates the full execution of a technique variant that is genuinely low-footprint from a process creation standpoint. The primary detection lever is PowerShell 4688 command-line logging, which captures the exact API call. Without command-line logging, this technique would leave almost no process-level trace. The dataset is useful for testing whether detections correctly handle pure PowerShell API-based enumeration distinct from binary-spawning enumeration.

Because neither the defended nor undefended execution triggers Defender (the API is legitimate), this dataset is most valuable for exercising PS script block logging-based detection pipelines rather than for studying endpoint protection bypass behavior.

## Detection Opportunities Present in This Data

1. EID 4688 command line containing `[System.Security.Principal.WindowsIdentity]::GetCurrent()` is the primary and most reliable detection signal for this technique variant.

2. EID 4104 script block logging containing `WindowsIdentity`, `GetCurrent`, or `Out-File` targeting a `.txt` file can detect the specific output-to-disk pattern even when the command line is obfuscated.

3. The pattern of PowerShell spawning a child PowerShell with a `& { ... }` inline script block, particularly when the block contains identity or user enumeration APIs, is worth flagging for follow-on investigation.

4. Sysmon EID 1 process creation for `powershell.exe` with parent `powershell.exe` and a command line containing `.NET` reflection patterns or security principal API calls provides a detection anchor even without dedicated PowerShell logging.

5. Correlating EID 4688 for `powershell.exe` executing `Remove-Item` targeting a recently-created `.txt` file with a prior execution block containing discovery API calls can reveal the pattern of collect-and-clean used in this test.
