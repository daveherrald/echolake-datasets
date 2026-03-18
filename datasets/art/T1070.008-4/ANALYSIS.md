# T1070.008-4: Clear Mailbox Data — Copy and Modify Mailbox Data on Windows

## Technique Context

T1070.008 Clear Mailbox Data represents adversaries' attempts to eliminate traces of their activities from email systems by manipulating or deleting mailbox contents. This technique is part of the Defense Evasion tactic, where attackers seek to cover their tracks after compromising email accounts or systems. In enterprise environments, this could involve clearing sent items, deleted items, or specific email threads that contain evidence of malicious activities. The detection community typically focuses on unusual email deletion patterns, PowerShell interactions with Exchange/Outlook APIs, and filesystem operations targeting mail storage locations like PST files or Exchange database paths.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation targeting the Teams/Skype for Business mail storage directory structure. The key technique evidence appears in:

**Security Event 4688**: Process creation showing the full PowerShell command line that creates a "copy" directory, copies mailbox data, and modifies the copied files:
`"powershell.exe" & {New-Item -Path \"C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\copy\" -ItemType Directory -ErrorAction Ignore; Get-ChildItem -Path \"C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\" -Exclude copy | ForEach-Object { Copy-Item -Path $_.FullName -Destination \"C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\copy\" -Recurse -Force -ErrorAction Ignore }; Get-ChildItem -Path \"C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\copy\" -File | ForEach-Object { Add-Content -Path $_.FullName -Value \"Modification for Atomic Red Test\" -ErrorAction Ignore }}`

**PowerShell Events 4103/4104**: Script block logging captures the individual cmdlet invocations including `New-Item`, `Get-ChildItem`, `Copy-Item`, and `Add-Content` operations targeting the Unistore data directory.

**Sysmon Events**: Process creation (EID 1) for both `whoami.exe` and the child PowerShell process, along with extensive image loading events (EID 7) showing .NET framework and Windows Defender integration during PowerShell execution. File creation events (EID 11) show PowerShell profile data creation.

## What This Dataset Does Not Contain

The dataset simulates mailbox data modification rather than actual email system interaction. There are no events showing:
- Direct Outlook or Exchange API calls
- PST file manipulation
- MAPI operations
- Network connections to Exchange servers
- Registry modifications related to Outlook profiles
- Actual mailbox database interactions

The target directory `C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data` appears to be empty or non-existent on this system (the machine account ACME-WS02$ doesn't have a typical user profile structure), so the actual file operations likely had no effect. The PowerShell commands all include `-ErrorAction Ignore` which would suppress any file not found errors.

## Assessment

This dataset provides limited utility for detecting real-world mailbox clearing attacks. While it demonstrates the PowerShell techniques an attacker might use, the simulation targets a non-standard directory path and doesn't interact with actual email storage mechanisms. The telemetry is valuable for understanding PowerShell-based file system manipulation patterns but lacks the email-specific artifacts that would characterize genuine T1070.008 behavior. The extensive process monitoring and PowerShell logging do provide good coverage of the execution environment and could support detection of similar file manipulation techniques targeting actual mailbox storage locations.

## Detection Opportunities Present in This Data

1. **PowerShell command line analysis** - Security 4688 events containing file operations targeting messaging application data directories (`AppData\Local\Comms`, `AppData\Local\Microsoft\Outlook`)

2. **Bulk file copying patterns** - PowerShell 4103 events showing `Copy-Item` cmdlet usage with recursive parameters and error suppression in messaging contexts

3. **File modification after copying** - Sequential PowerShell operations showing copy followed by `Add-Content` or similar modification cmdlets on the same directory structure

4. **Mailbox directory enumeration** - PowerShell `Get-ChildItem` operations targeting known email storage paths with exclusion filters

5. **Process tree analysis** - Parent-child PowerShell process relationships where child processes perform file operations on email-related directories

6. **PowerShell execution policy bypass** - Detection of `Set-ExecutionPolicy Bypass` in contexts involving file operations on communication application data

7. **Sysmon process access events** - EID 10 events showing PowerShell processes accessing other processes during mailbox-related operations

8. **Suspicious directory creation** - File creation events (Sysmon EID 11) for backup or staging directories within email application data paths
