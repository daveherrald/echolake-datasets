# T1040-16: Network Sniffing — PowerShell Network Sniffing

## Technique Context

T1040 (Network Sniffing) involves capturing network traffic to harvest credentials, session tokens, or sensitive data from network communications. This test uses Windows' built-in `NetEventSession` cmdlets — a legitimate Windows network diagnostics API — to capture packets to an ETL (Event Trace Log) file. The full command creates a session named `Capture007`, adds a packet capture provider with a truncation length of 100 bytes, starts the session, immediately stops it, then removes the session. The output file `$ENV:Temp\sniff.etl` contains raw packet data in the Windows ETW (Event Tracing for Windows) format.

Using `New-NetEventSession` and related cmdlets is a living-off-the-land approach to network sniffing that requires no external tools. These cmdlets are part of the `NetworkEventSession` PowerShell module that ships with Windows and operate through WMI providers — hence the `wmiprvse.exe` process involvement in the capture. The ETL output file can be analyzed post-capture with `Get-NetEventPacketCapture` or converted to PCAP for standard network analysis tools.

This technique is particularly concerning in environments that assume Wireshark or tcpdump are the only sniffing tools to monitor. The `NetEventSession` cmdlets are regularly used by Windows administrators for legitimate network diagnostics, so process-level detection requires contextual analysis. The primary detection signals are the creation of the ETL capture file and the use of the `New-NetEventSession`/`Add-NetEventPacketCaptureProvider`/`Start-NetEventSession` cmdlet sequence.

## What This Dataset Contains

This dataset contains 226 events: 103 PowerShell events, 49 Security events, 67 Sysmon events, 6 Task Scheduler events, and 1 System event. This is significantly larger than the defended dataset (43 Sysmon, 23 Security, 45 PowerShell), reflecting that the undefended version allows the WMI-based capture infrastructure to fully initialize, generating additional Sysmon and Security events.

The Security channel reveals interesting enumeration activity triggered by the network capture session: 5 EID 4798 events enumerate local user accounts (Administrator, Guest, DefaultAccount, mm11711, WDAGUtilityAccount). These enumeration events appear to be triggered by the WMI network capture provider performing a security context check or by the Windows networking stack validating the caller's group memberships. There are also 10 EID 5379 (credential manager access) events and 2 EID 4624 (logon) plus 2 EID 4672 (special privilege logon) events. The cleanup EID 4688 shows `powershell.exe & {del $ENV:Temp\sniff.etl}`, confirming the ETL file was created and then deleted.

The Sysmon channel has 21 EID 13 (registry write) events, 19 EID 7 (image load) events, and 16 EID 11 (file create) events. The registry writes reflect Windows Update activity (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`) that coincides with the test timing. The 16 file create events are primarily Windows Update metadata DLLs being downloaded to `C:\Windows\SoftwareDistribution\Download\` — background OS activity during the capture window. Sysmon EID 1 shows `wmiprvse.exe` being launched by `svchost.exe -k DcomLaunch`, tagged `technique_id=T1047` — the WMI provider activation for the network capture session. EID 7 for `wmiprvse.exe` loading `wmiutils.dll` (tagged `technique_id=T1047`) confirms the WMI provider initialization.

A System EID 4 event ("Service stopped") accompanies the test, reflecting the network capture session stopping.

The Task Scheduler channel shows failed task launches (`\Microsoft\Windows\UpdateOrchestrator\USO_UxBroker`, EID 101/203) and task updates for `Schedule Work` and `Schedule Wake To Work` — all background Windows Update orchestration unrelated to the technique.

The 4798 user enumeration events are unique to this undefended execution: in the defended dataset, the capture session may be disrupted before full WMI initialization occurs, preventing the security context verification that triggers these events. Their presence here represents a full execution artifact.

## What This Dataset Does Not Contain

The PowerShell script blocks containing the actual `New-NetEventSession`, `Add-NetEventPacketCaptureProvider`, and `Start-NetEventSession` cmdlet invocations are not present in the sampled EID 4104 events. The 5 EID 4103 (module logging) events would contain the cmdlet invocation records, but none appear in the sample set. The full dataset's PowerShell channel will contain this content, but it is not surfaced in samples here.

No Sysmon EID 11 event captures the creation of `$ENV:Temp\sniff.etl` — the ETL capture file. This is likely filtered by the Sysmon configuration (`.etl` files or SoftwareDistribution paths may be excluded). The file existence is confirmed only by the cleanup command's `del $ENV:Temp\sniff.etl` in the EID 4688 command line.

The actual captured packet data is not represented in any event. No network connection events (Sysmon EID 3) show the network capture session's operation.

## Assessment

This dataset provides strong detection engineering value for WMI-based PowerShell network sniffing. The combination of `wmiprvse.exe` initialization (Sysmon EID 1 tagged T1047), the group/user enumeration burst (Security EID 4799/4798) triggered by the capture provider security check, and the cleanup command explicitly referencing `sniff.etl` creates a multi-event chain. The unusually large volume of Security group enumeration events (19 EID 4799 entries covering all local groups) is a distinctive side-effect of this specific technique variant that can serve as a behavioral fingerprint.

The defended-vs-undefended comparison is stark in this dataset: the undefended version generates 49 Security events and 67 Sysmon events versus 23 and 43 in the defended case, primarily because the capture session fully initializes and runs through its complete lifecycle.

## Detection Opportunities Present in This Data

1. Security EID 4688 or Sysmon EID 1 for `powershell.exe` with a command line containing `New-NetEventSession`, `Add-NetEventPacketCaptureProvider`, or `Start-NetEventSession` — this cmdlet sequence is the definitive indicator for this technique variant.

2. EID 4688 showing `del $ENV:Temp\sniff.etl` or similar deletion of an ETL file from a temp directory indicates post-capture cleanup; the ETL extension is the canonical network capture output format for this technique.

3. Sysmon EID 1 for `wmiprvse.exe` launching in close temporal proximity to a PowerShell execution that contains network capture cmdlets, tagged `technique_id=T1047`, connects the WMI provider activation to the sniffing activity.

4. A burst of Security EID 4799 (local group membership enumerated) events covering multiple or all local groups within a short time window, when correlated with a concurrent PowerShell execution, can indicate the security validation triggered by `NetEventSession` provider initialization.

5. EID 4103 (PowerShell module logging) events containing `NetEventSession` cmdlet invocations with `LocalFilePath` pointing to `$env:TEMP` or other writable paths capture the full parameter set of the capture session configuration.

6. Security EID 5379 (credential manager read) events occurring in close succession during a PowerShell execution involving network APIs can indicate credential access as a component of or adjacent to network capture operations.
