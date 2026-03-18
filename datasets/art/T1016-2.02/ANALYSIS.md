# T1016-2: System Network Configuration Discovery — List Windows Firewall Rules

## Technique Context

T1016 System Network Configuration Discovery encompasses any technique an adversary uses to gather information about the victim's network setup. Firewall rule enumeration is a particularly valuable subset: knowing the host-based firewall configuration tells an attacker which ports and protocols are allowed, which processes are explicitly permitted inbound or outbound connections, and whether there are any rules that would expose gaps in network segmentation. This intelligence directly informs decisions about what channels to use for C2 communication and lateral movement.

The `netsh advfirewall firewall show rule name=all` command dumps every configured Windows Firewall rule including name, direction, protocol, local and remote port ranges, profile (Domain/Private/Public), action, and program path. On a domain-joined workstation, this can reveal dozens to hundreds of rules including application-specific entries, remote management rules, and any rules created by security tools.

This technique works identically with or without Defender — `netsh.exe` is a trusted system binary and its firewall query subcommands are legitimate administrative operations. The dataset content is therefore essentially the same in both the defended and undefended variants; the undefended run differs primarily in concurrent OS activity.

## What This Dataset Contains

The dataset spans approximately 9 seconds (22:56:07 to 22:56:16) and captures the complete firewall enumeration execution chain.

The Security channel's five EID 4688 events trace the full process lineage. The parent PowerShell process (PID `0x1850`) first spawns `whoami.exe` for user discovery (`"C:\Windows\system32\whoami.exe"`), then spawns `cmd.exe` with:

```
"cmd.exe" /c netsh advfirewall firewall show rule name=all
```

That `cmd.exe` (PID `0x8b8`) in turn spawns `netsh.exe` (PID `0x1b38`) with:

```
netsh  advfirewall firewall show rule name=all
```

(Note the double space after `netsh` — this is the cmd.exe parsing artifact when passing the command through the shell. The actual `netsh` invocation is correct.)

The same PowerShell then spawns a second `whoami.exe` and a final empty `cmd.exe /c` — both are the ART test framework performing post-execution bookkeeping. All processes run as NT AUTHORITY\SYSTEM (subject SID `S-1-5-18`, logon `0x3e7`).

The Sysmon channel shows process creation events (EID 1) confirming the chain, plus 8 EID 7 (ImageLoad) events for PowerShell loading .NET runtime components (`mscoree.dll`, `mscoreei.dll`, `clr.dll`, `clrjit.dll`) — the standard PowerShell startup signature. Four EID 10 (ProcessAccess) events show PowerShell accessing child processes with `0x1fffff` access rights. The named pipe creation (Sysmon EID 17) for `\PSHost.*.powershell` from the parent PowerShell process is the test framework establishing its IPC channel.

Compared to the defended version (29 sysmon, 19 security, 34 PowerShell), the undefended run has fewer events (20 sysmon, 5 security, 94 PowerShell) despite having Defender disabled. This appears to reflect a quieter moment in VM activity rather than any technique-specific difference — the defended run captured more concurrent background process activity.

## What This Dataset Does Not Contain

The actual firewall rule output is not captured in any event log — `netsh` writes to stdout, which is consumed by cmd.exe and displayed in the console but not persisted to any auditable log. The enumeration results are visible only to whoever is monitoring the console or has redirected output to a file.

There are no Sysmon EID 3 (network connection) events since `netsh advfirewall show` queries local policy without making network connections. There are no registry access events (Sysmon EID 12/13) despite `netsh` reading firewall configuration from the registry — the registry reads occur below the threshold monitored by this Sysmon configuration.

The PowerShell EID 4104 samples contain only framework boilerplate (Set-StrictMode, ErrorCategory_Message). The ART test framework command that initiated the firewall enumeration is captured in Security EID 4688 but is not in the PowerShell script block logs since the actual `netsh` invocation goes through `cmd.exe` rather than native PowerShell cmdlets.

## Assessment

This is a clean, simple dataset with a clear process execution chain and strong command-line evidence. The Security EID 4688 events provide the complete `netsh advfirewall firewall show rule name=all` command captured in two places — once as the cmd.exe argument and once as the netsh.exe process creation. The dataset is suitable for building and testing basic process execution detections for firewall discovery. Because this technique is not blocked by Defender, the undefended and defended datasets are structurally similar and both provide the same core detection surfaces.

## Detection Opportunities Present in This Data

1. Security EID 4688 showing `netsh.exe` created with the arguments `advfirewall firewall show rule name=all` is the primary indicator. This specific subcommand combination is rarely used in legitimate automated administration.

2. The parent-child chain `powershell.exe → cmd.exe → netsh.exe` where cmd.exe's command line contains `netsh advfirewall firewall show rule` can be matched as a behavioral sequence across consecutive EID 4688 events within the same session.

3. Sysmon EID 1 capturing `netsh.exe` with the `advfirewall firewall show rule` command line provides the same indicator with additional metadata (hashes, parent process GUID) for correlation.

4. The combination of `whoami.exe` execution immediately before `cmd.exe /c netsh advfirewall` from the same parent process (PowerShell running as SYSTEM) is the ART test framework reconnaissance-and-execute pattern — seeing discovery commands bookending network configuration queries is a useful behavioral cluster.

5. PowerShell (running as SYSTEM) spawning cmd.exe which then spawns `netsh.exe` with firewall enumeration arguments is a process ancestry pattern worth modeling — legitimate network administration would typically invoke `netsh` directly or use `Get-NetFirewallRule` PowerShell cmdlets.
