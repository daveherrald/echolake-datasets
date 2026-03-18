# T1070.008-1: Clear Mailbox Data — Copy and Delete Mailbox Data on Windows

## Technique Context

T1070.008 Clear Mailbox Data represents an adversary's attempt to remove traces of their activity by deleting email communications. While traditionally focused on mail server environments, this technique can extend to client-side mailbox data, cached messages, and local storage of email applications. Attackers may target mailbox data to eliminate evidence of phishing campaigns, data exfiltration communications, or other email-based attack vectors. The detection community typically monitors for bulk email deletions, access to mail storage directories, and PowerShell interactions with mail-related APIs or file systems containing email data.

## What This Dataset Contains

This dataset captures a PowerShell-based simulation targeting Microsoft Teams/Communications data rather than traditional email. The core malicious activity appears in PowerShell event 4104 with the script block:

```
New-Item -Path "C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\copy" -ItemType Directory -ErrorAction Ignore
Get-ChildItem -Path "C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data" -Exclude copy | ForEach-Object { Copy-Item -Path $_.FullName -Destination "C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\copy" -Recurse -Force -ErrorAction Ignore }
Remove-Item -Path "C:\Users\$env:USERNAME\AppData\Local\Comms\Unistore\data\copy" -Recurse -Force -ErrorAction Ignore
```

The technique creates a backup copy directory, copies all Unistore data to it, then deletes the copy - simulating a copy-and-delete anti-forensics operation. Security event 4688 shows the PowerShell command line execution, while PowerShell events 4103 capture the individual cmdlet invocations (New-Item, Get-ChildItem, ForEach-Object with Copy-Item, and Remove-Item). Sysmon events 1 and 10 show the PowerShell process creation and inter-process communication, with the ProcessCreate events tagged with T1083 (File and Directory Discovery) reflecting the directory enumeration component.

## What This Dataset Does Not Contain

The dataset lacks evidence of actual mailbox data manipulation since the target directory (C:\Users\ACME-WS02$\AppData\Local\Comms\Unistore\data) likely doesn't exist on this test system. No file system events show actual file copies or deletions, suggesting the operations completed without errors but processed no actual data. Missing are Sysmon FileCreate/FileDelete events (EIDs 11/23) for the Unistore directory contents, object access audit events that would show file operations, and any evidence of legitimate Microsoft Teams or email client data being affected. The simulation demonstrates the technique pattern without impacting real communication data.

## Assessment

This dataset provides moderate value for detection engineering focused on PowerShell-based data clearing operations. The PowerShell script block logging (EID 4104) clearly captures the malicious intent and technique pattern, while command invocation logging (EID 4103) provides detailed parameter visibility. The command-line arguments visible in Security EID 4688 offer an additional detection vector. However, the dataset's utility is limited by the absence of actual file system impacts and the simulation nature targeting a likely non-existent directory. The telemetry quality is excellent for detecting the attack pattern but doesn't demonstrate the technique's real-world filesystem impact or provide indicators for post-execution forensic analysis.

## Detection Opportunities Present in This Data

1. **PowerShell Script Block Analysis**: Monitor EID 4104 for scripts containing combinations of New-Item, Get-ChildItem with -Exclude, Copy-Item with -Recurse -Force, and Remove-Item targeting communication/mail directories.

2. **Suspicious Directory Operations Pattern**: Detect PowerShell command sequences creating temporary directories, copying contents while excluding the temp directory, then deleting the temp directory - classic anti-forensics pattern.

3. **Mail Data Directory Targeting**: Alert on PowerShell access to known mail/communication storage paths like AppData\Local\Comms\, Outlook data directories, or other mail client storage locations.

4. **Bulk File Operations with Error Suppression**: Monitor for PowerShell cmdlets using -ErrorAction Ignore combined with -Force parameters on file operations, indicating attempts to bypass normal access controls.

5. **Command Line Pattern Detection**: Use Security EID 4688 to detect PowerShell processes with command lines containing the specific copy-exclude-delete pattern targeting communication directories.

6. **Process Relationship Analysis**: Correlate Sysmon EID 1 ProcessCreate events showing PowerShell spawning from suspicious parent processes combined with file operation patterns.

7. **PowerShell Module Usage**: Monitor EID 4103 CommandInvocation events for rapid sequences of New-Item, Get-ChildItem, Copy-Item, and Remove-Item operations with mailbox-related paths.
