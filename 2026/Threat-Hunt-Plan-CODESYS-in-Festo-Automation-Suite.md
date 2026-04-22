# Threat Hunt Plan: ICSA-26-076-01 — CODESYS in Festo Automation Suite

> Date: 2026-03-23 | Revision: 1.0

1. Hunt Objective and Scope

This hunt targets active exploitation or post-exploitation activity related to the 128 CVEs disclosed in CISA ICS Advisory ICSA-26-076-01, affecting CODESYS Development System components bundled in Festo Automation Suite (FAS) versions 2.8.0.137 and earlier. The threat model prioritizes the nine Critical-severity (CVSS 9.8) unauthenticated remote code execution paths in the CODESYS V3 web server, CODESYS Control Runtime, Wibu CodeMeter packet parser, and CmpGateway component. Secondary objectives cover exploitation of high-severity authenticated escalation paths (CVE-2022-4046, CVE-2023-6357) and forced-browsing access to CODESYS Visualization assets (CVE-2025-2595).

The hunt scope encompasses all engineering workstations and Windows servers with Festo Automation Suite or standalone CODESYS Development System installed, plus all PLCs and controllers accessible via CODESYS gateway from those hosts. The network scope includes the IT/OT DMZ, engineering LAN, and any VLAN containing CODESYS runtime (TCP/UDP 1217) or Wibu CodeMeter (TCP/UDP 22350) services. Time window: 90 days prior to hunt initiation, with elevated focus on traffic spikes and anomalous process activity in the 30 days prior to this advisory date.

2. Hypotheses and Hunt Procedures

Hypothesis 1: A remote attacker has exploited CVE-2019-13548, CVE-2019-18858, CVE-2020-10245, or CVE-2021-33485 to achieve unauthenticated remote code execution via the CODESYS V3 web server, observable as unexpected child processes or network connections spawned from the CODESYS runtime process in endpoint telemetry.

MITRE ATT&CK: Initial Access | T1190 — Exploit Public-Facing Application | An attacker exploits a stack or heap buffer overflow in the CODESYS web server listening on TCP 8080/443 to gain code execution on the engineering workstation without credentials.

### Collection Queries

CrowdStrike Falcon — Collect child processes of CODESYS runtime:

```text
#event_simpleName = "ProcessRollup2"

| ParentBaseFileName = "CoDeSysControlWinSysService64.exe"

OR ParentBaseFileName = "codesyscontrol.exe"

OR ParentBaseFileName = "CODESYS.exe"

| table([ComputerName, ParentBaseFileName, FileName, ImageFileName, CommandLine, RawProcessId, ContextTimeStamp])
```

CrowdStrike Falcon — Collect outbound network connections from CODESYS process:

```bash
#event_simpleName = "NetworkConnectIP4"

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName]), limit=100000)},

field=[aid,RawProcessId],

include=[ImageFileName,FileName,CommandLine,ParentBaseFileName]

)

| FileName = /codesys/i OR ParentBaseFileName = /codesys/i

| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName])

tcpdump — Capture CODESYS web server traffic for payload inspection:

tcpdump -i eth0 -w /captures/codesys_web\_%Y%m%d\_%H%M%S.pcap -G 3600 -C 500 \\
```

"tcp port 8080 or tcp port 443 or tcp port 4840"

Datadog Log Search — Collect CODESYS process spawns (Windows endpoint):

```yaml
source:windows message:"CoDeSysControlWinSysService64.exe" status:error

// time range: last 90 days; filter to engineering workstation hostnames

source:windows message:"codesyscontrol.exe" message:"cmd.exe OR powershell.exe OR wscript.exe"

// time range: last 90 days
```

Datadog Live Process Monitoring (Infrastructure \> Processes):

```text
command:CoDeSysControl user:SYSTEM
```

Windows Event Collection — Capture process creation from CODESYS parent (Event ID 4688):

```powershell
Get-WinEvent -FilterHashtable @{

LogName = 'Security'

Id = 4688

StartTime = (Get-Date).AddDays(-90)

} | Where-Object {

$_.Properties\[13\].Value -match 'codesys' -or

$_.Properties\[5\].Value -match 'codesys'

} | Select-Object TimeCreated,

@{N='NewProcess'; E={$_.Properties\[5\].Value}},

@{N='ParentProcess'; E={$_.Properties\[13\].Value}},

@{N='CommandLine'; E={$_.Properties\[8\].Value}} |

Export-Csv -Path C:\hunt\codesys_children_4688.csv -NoTypeInformation
```

OT/ICS — Export CODESYS gateway connection log from engineering workstation:

\# Export CODESYS Communication Gateway log directory

\# Default path: C:\ProgramData\CODESYS\GatewayService\Logs\\

```powershell
Get-ChildItem "C:\ProgramData\CODESYS\GatewayService\Logs\\ -Filter "\*.log" |

Copy-Item -Destination C:\hunt\gateway_logs\\

YARA — Scan CODESYS installation directory for dropped tools or payloads:

yara -r C:\hunt\rules\codesys_exploit_artifacts.yar \\

"C:\Program Files\CODESYS\\ >> C:\hunt\codesys_dir_yara_hits.txt
```

### Analysis Queries

CrowdStrike Falcon — Detect unexpected process types spawned by CODESYS (rare child analysis):

```text
#event_simpleName = "ProcessRollup2"

| ParentBaseFileName = "CoDeSysControlWinSysService64.exe"

OR ParentBaseFileName = "codesyscontrol.exe"

| groupBy([FileName, CommandLine], function=count(), limit=100000)

| sort(\_count, order=asc, limit=50)
```

CrowdStrike Falcon — Detect new executables written by CODESYS runtime process:

```text
#event_simpleName = "NewExecutableWritten"

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([FileName,CommandLine]), limit=100000)},

field=[aid,RawProcessId],

include=[FileName,CommandLine]

)

| FileName = /codesys/i

| table([ComputerName, FileName, CommandLine, TargetFileName, FilePath])
```

Wireshark — Identify oversized or malformed requests to CODESYS web server:

tcp.port == 8080 and tcp.len \> 8000

\# tshark equivalent:

```bash
tshark -r codesys_web.pcap -Y "tcp.port == 8080 && tcp.len > 8000" \\

-T fields -e frame.time -e ip.src -e tcp.len >> codesys_large_requests.txt
```

Datadog Log Analytics — Detect CODESYS child process anomalies (Table view):

```text
source:windows message:"CoDeSysControlWinSysService64.exe"

// Analytics: Table view; group by host, message; time range: last 90 days

// Alert on any row where child process is cmd.exe, powershell.exe, or wscript.exe
```

Datadog Audit Trail — Detect unauthorized access to engineering workstation accounts used by CODESYS service:

```text
source:datadog @evt.category:user_access @evt.name:login

// Filter for accounts matching CODESYS service account naming convention; time range: last 90 days
```

Datadog Monitor — Alert on new process spawned by CODESYS service:

```text
Type: Log Alert

Query: source:windows "CoDeSysControlWinSysService64.exe" ("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "mshta.exe")

Evaluation window: last 5 minutes

Alert condition: count > 0

Message: "ALERT: Unexpected shell process spawned by CODESYS runtime — possible CVE-2019-13548/CVE-2020-10245 exploitation — immediate investigation required @security-oncall"
```

Prerequisites: Windows Security Event Logs (Event ID 4688) must be forwarded to Datadog; process command-line audit must be enabled (GPO: Audit Process Creation + Include command line in process creation events)

Windows PowerShell Analysis — Hunt CODESYS-spawned shells and injections:

```powershell
Get-WinEvent -FilterHashtable @{

LogName = 'Security'

Id = 4688

StartTime = (Get-Date).AddDays(-90)

} | Where-Object {

$_.Properties\[13\].Value -match 'codesys' -and

$_.Properties\[5\].Value -match 'cmd\\exe|powershell|wscript|mshta|rundll32|regsvr32'

} | Select-Object TimeCreated,

@{N='Shell'; E={$_.Properties\[5\].Value}},

@{N='Parent'; E={$_.Properties\[13\].Value}},

@{N='CmdLine';E={$_.Properties\[8\].Value}} |

Export-Csv C:\hunt\codesys_shell_spawn.csv -NoTypeInformation

YARA Memory Scan — Scan CODESYS runtime process memory for injected shellcode:
```

\# Enumerate CODESYS PIDs and scan memory

```powershell
Get-Process | Where-Object { $\_.Name -match 'codesys|CoDeSys' } | ForEach-Object {

yara -p $\_.Id C:\hunt\rules\injected_shellcode.yar 2>>C:\hunt\yara_errors.txt

} >> C:\hunt\codesys_memory_yara_hits.txt
```

\# CrowdStrike RTR alternative: Run-Script -CloudFile codesys_yara_scan.ps1

OT/ICS — Correlate unexpected CODESYS gateway connections with historian anomalies:

\# On Emerson DeltaV / Wonderware: export process variable change log for engineering workstation source address

\# On OSIsoft PI: query PI Data Archive for AF event frames tagged to workstation gateway IP in the hunt window

\# On Claroty/Nozomi: export "New Connection" alerts for CODESYS protocol (port 1217) from engineering VLAN

Hypothesis 2: A remote attacker has exploited CVE-2020-14509 or CVE-2023-3935 to achieve unauthenticated remote code execution via the Wibu CodeMeter license daemon, observable as anomalous network traffic to TCP/UDP port 22350, unexpected process execution from the CodeMeter service, or memory artifacts associated with post-exploitation frameworks in the CodeMeter process.

MITRE ATT&CK: Initial Access | T1190 — Exploit Public-Facing Application | An attacker sends specially crafted packets to the CodeMeter daemon (TCP/UDP 22350) to corrupt heap memory and achieve code execution without credentials, exploiting CWE-805 (CVE-2020-14509) or CWE-787 (CVE-2023-3935).

### Collection Queries

CrowdStrike Falcon — Collect child processes of CodeMeter daemon:

```text
#event_simpleName = "ProcessRollup2"

| ParentBaseFileName = "CodeMeter.exe" OR ParentBaseFileName = "CodeMeterCC.exe"

| table([ComputerName, ParentBaseFileName, FileName, ImageFileName, CommandLine, RawProcessId, ContextTimeStamp])
```

CrowdStrike Falcon — Collect outbound connections from CodeMeter:

```bash
#event_simpleName = "NetworkConnectIP4"

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine]), limit=100000)},

field=[aid,RawProcessId],

include=[ImageFileName,FileName,CommandLine]

)

| FileName = "CodeMeter.exe"

| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine])

tcpdump — Capture CodeMeter traffic for packet analysis:

tcpdump -i eth0 -w /captures/codemeter\_%Y%m%d\_%H%M%S.pcap -G 3600 -C 200 \\
```

"port 22350"

Datadog Log Search — Collect CodeMeter service errors:

```yaml
source:windows message:"CodeMeter" status:error

// time range: last 90 days
```

Datadog Live Process Monitoring:

```text
command:CodeMeter user:SYSTEM
```

Windows Event Collection — CodeMeter service crashes (Event ID 7034, 1000):

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7034; StartTime=(Get-Date).AddDays(-90)} |

Where-Object { $\_.Message -match 'CodeMeter' } |

Select-Object TimeCreated, Message |

Export-Csv C:\hunt\codemeter_crashes.csv -NoTypeInformation

Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=(Get-Date).AddDays(-90)} |

Where-Object { $\_.Message -match 'CodeMeter' } |

Select-Object TimeCreated, Message |

Export-Csv C:\hunt\codemeter_appcrash.csv -NoTypeInformation

YARA — Scan CodeMeter installation for dropped payloads:

yara -r C:\hunt\rules\codemeter_exploit_artifacts.yar \\

"C:\Program Files (x86)\CodeMeter\\ >> C:\hunt\codemeter_dir_yara_hits.txt
```

### Analysis Queries

CrowdStrike Falcon — Detect rare children of CodeMeter (rarity hunt):

```text
#event_simpleName = "ProcessRollup2"

| ParentBaseFileName = "CodeMeter.exe"

| groupBy([FileName, CommandLine], function=count(), limit=100000)

| sort(\_count, order=asc, limit=25)
```

CrowdStrike Falcon — Detect inbound packet volume spikes to port 22350 (rate analysis):

```text
#event_simpleName = "NetworkReceiveAcceptIP4"

| LocalPort = "22350"

| groupBy([ComputerName, RemoteAddressIP4], function=count(), limit=100000)

| sort(\_count, order=desc, limit=50)
```

Wireshark — Detect oversized or malformed CodeMeter packets:

udp.port == 22350 and udp.length \> 1400

tcp.port == 22350 and tcp.len \> 4096

\# tshark equivalent for oversized packets:

```bash
tshark -r codemeter.pcap -Y "(udp.port == 22350 && udp.length > 1400) || (tcp.port == 22350 && tcp.len > 4096)" \\

-T fields -e frame.time -e ip.src -e ip.len >> codemeter_oversized.txt
```

Datadog Log Analytics — CodeMeter crash and error rate by host:

```yaml
source:windows message:"CodeMeter" status:error

// Analytics: Timeseries view; group by host; time range: last 90 days

// Spike in errors correlates with exploit attempts causing service instability
```

Datadog Audit Trail — Detect CodeMeter license tampering via service account access:

```text
source:datadog @evt.category:user_management @evt.name:user.login

// Filter for service accounts associated with CodeMeter; flag logins outside business hours
```

Datadog Monitor — Alert on CodeMeter service crash:

```yaml
Type: Log Alert

Query: source:windows message:"CodeMeter" (status:error OR "application error" OR "faulting application")

Evaluation window: last 10 minutes

Alert condition: count > 2

Message: "ALERT: CodeMeter service crash detected — possible CVE-2020-14509/CVE-2023-3935 exploitation attempt — @security-oncall"
```

Prerequisites: Windows System and Application Event Logs must be forwarded to Datadog; WinRM or Datadog Agent must be installed on engineering workstations

```powershell
YARA Memory Scan — Scan CodeMeter process memory for post-exploitation artifacts:

Get-Process | Where-Object { $\_.Name -match 'CodeMeter' } | ForEach-Object {

yara -p $\_.Id C:\hunt\rules\post_exploitation_memory.yar 2>>C:\hunt\yara_errors.txt

} >> C:\hunt\codemeter_memory_hits.txt
```

OT — Correlate CodeMeter service restart times with control system events:

\# Cross-reference CodeMeter service crash timestamps with SCADA alarm log for unexpected controller disconnections

\# Historian query: select all "communication lost" alarms for CODESYS-managed controllers in the hunt window

Hypothesis 3: A threat actor has exploited CVE-2019-9010 to hijack the CODESYS CmpGateway communication channel and pivot from the engineering workstation to downstream PLCs, observable as unexpected CODESYS protocol connections to controller IP addresses not associated with any authorized download or monitoring session.

MITRE ATT&CK: Lateral Movement / ATT&CK for ICS T0817 — Drive-by Compromise; T0866 — Exploitation of Remote Services | Gateway channel hijacking to reach PLCs from the engineering workstation, exploiting the ownership verification failure in CmpGateway prior to CODESYS 3.5.14.20.

### Collection Queries

CrowdStrike Falcon — Collect all outbound CODESYS runtime connections to OT network ranges:

```bash
#event_simpleName = "NetworkConnectIP4"

| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName]), limit=100000)},

field=[aid,RawProcessId],

include=[ImageFileName,FileName,CommandLine,ParentBaseFileName]

)

| FileName = /codesys/i OR FileName = "CodeMeter.exe"

| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ContextTimeStamp])

tcpdump — Rolling PCAP capture on engineering workstation uplink to OT network:

tcpdump -i eth1 -w /captures/ot_uplink\_%Y%m%d\_%H%M%S.pcap -G 3600 -C 500 \\
```

"tcp port 1217 or udp port 1217 or port 11740"

Datadog Log Search — Collect CODESYS gateway connection events:

```text
source:windows message:"GatewayService" message:"connection"

// time range: last 90 days; engineering workstation hostnames
```

Windows Event Collection — CODESYS gateway service network connections (Sysmon Event ID 3):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3; StartTime=(Get-Date).AddDays(-90)} |

Where-Object { $\_.Message -match 'codesys|GatewayService' } |

Select-Object TimeCreated,

@{N='Image'; E={($\_.Message -split '\n' | Select-String 'Image:').Line}},

@{N='DestIP'; E={($\_.Message -split '\n' | Select-String 'DestinationIp:').Line}},

@{N='DestPort'; E={($\_.Message -split '\n' | Select-String 'DestinationPort:').Line}} |

Export-Csv C:\hunt\codesys_gw_sysmon_net.csv -NoTypeInformation
```

OT/ICS — Export OT monitoring platform connection baseline:

\# Claroty: Admin \> Asset Inventory \> Export connections for CODESYS gateway protocol (port 1217)

\# Dragos: Asset \> Network Connections \> filter source = engineering workstation IP range

\# Nozomi: Assets \> Connections \> filter protocol = CODESYS

\# Baseline: compare exported connections against authorized engineering session schedule

```text
YARA — Scan CODESYS gateway log directory for injected payloads:

yara -r C:\hunt\rules\codesys_exploit_artifacts.yar \\

"C:\ProgramData\CODESYS\GatewayService\\ >> C:\hunt\gateway_dir_yara_hits.txt
```

### Analysis Queries

CrowdStrike Falcon — Frequency analysis of CODESYS gateway destination IPs (anomaly hunt):

```text
#event_simpleName = "NetworkConnectIP4"

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([FileName,CommandLine]), limit=100000)},

field=[aid,RawProcessId],

include=[FileName,CommandLine]

)

| FileName = /codesys/i

| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count(), limit=100000)

| sort(\_count, order=asc, limit=50)
```

Wireshark — Identify CODESYS gateway protocol sessions to new or unexpected controller IPs:

tcp.port == 1217 or udp.port == 1217

\# tshark — extract unique CODESYS destination IPs for comparison to authorized asset list:

```bash
tshark -r ot_uplink.pcap -Y "tcp.port == 1217 || udp.port == 1217" \\

-T fields -e ip.src -e ip.dst -e frame.time | sort -u >> codesys_gw_ips.txt
```

Datadog Log Analytics — CODESYS gateway session volume by destination host:

```text
source:windows message:"GatewayService"

// Analytics: Table view; group by host, message; time range: last 90 days

// Flag destinations not in the authorized PLC IP list
```

Datadog Audit Trail — Detect unauthorized changes to CODESYS gateway service configuration:

```text
source:datadog @evt.category:integration_management

// Filter for changes to integration configuration on engineering workstation hosts
```

Datadog Monitor — Alert on CODESYS gateway connection to new destination IP:

```text
Type: Log Alert

Query: source:windows message:"GatewayService" message:"new connection"

Evaluation window: last 5 minutes

Alert condition: count > 0

Message: "ALERT: CODESYS gateway new connection — possible CVE-2019-9010 channel hijacking — verify against authorized PLC session schedule @security-oncall"
```

Prerequisites: CODESYS GatewayService logs must be forwarded to Datadog via Datadog Agent custom log collection; Windows Sysmon (Event ID 3) forwarding must be enabled

SNMP — Poll engineering workstation uplink switch for traffic volume on OT-facing port:

```bash
snmpwalk -v2c -c public <switch-ip> 1.3.6.1.2.1.2.2.1.10.<ifIndex> # ifInOctets

snmpwalk -v2c -c public <switch-ip> 1.3.6.1.2.1.2.2.1.16.<ifIndex> # ifOutOctets
```

\# Compare against rolling 30-day baseline; flag deviations \> 2 standard deviations

OT — EtherNet/IP and CODESYS protocol anomaly analysis:

\# Wireshark filter for EtherNet/IP CIP commands on CODESYS-managed controllers:

enip && cip.service == 0x4c \# CIP Read Tag — unexpected bulk reads may indicate reconnaissance

enip && cip.service == 0x4d \# CIP Write Tag — flag writes outside maintenance windows

\# tshark — extract CIP service codes for offline analysis:

```powershell
tshark -r ot_uplink.pcap -Y "enip" \\

-T fields -e ip.src -e ip.dst -e cip.service -e frame.time >> cip_services.txt

YARA Memory Scan — Scan CODESYS gateway process for injected code:

Get-Process | Where-Object { $\_.Name -match 'GatewayService|codesys' } | ForEach-Object {

yara -p $\_.Id C:\hunt\rules\post_exploitation_memory.yar 2>>C:\hunt\yara_errors.txt

} >> C:\hunt\gateway_memory_hits.txt
```

Hypothesis 4: A low-privilege authenticated attacker has exploited CVE-2022-4046 or CVE-2023-6357 to escalate privileges on the engineering workstation, observable as CODESYS-related processes executing OS commands or writing files to system directories outside normal installation paths, and as unexpected privilege escalation events in Windows security logs.

MITRE ATT&CK: Privilege Escalation | T1068 — Exploitation for Privilege Escalation | A low-privilege attacker with CODESYS runtime access exploits an authenticated buffer overflow (CVE-2022-4046) or OS command injection via file system library functions (CVE-2023-6357) to escalate to SYSTEM or administrator privileges on the workstation.

### Collection Queries

CrowdStrike Falcon — Collect file write events from CODESYS processes to sensitive directories:

```text
#event_simpleName = "NewExecutableWritten"

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([FileName,CommandLine,AuthenticationId]), limit=100000)},

field=[aid,RawProcessId],

include=[FileName,CommandLine,AuthenticationId]

)

| FileName = /codesys/i

| FilePath = /System32|Windows\\Temp|ProgramData|Users\\.\*\\AppData/i

| table([ComputerName, FileName, CommandLine, TargetFileName, FilePath, AuthenticationId])
```

CrowdStrike Falcon — Collect CODESYS registry writes (privilege-level configuration changes):

```bash
#event_simpleName = "RegGenericValueUpdate"

| RegObjectName = /CODESYS|CodeMeter|Wibu/i

| join(

query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId]), limit=100000)},

field=[aid,ContextProcessId], key=[aid,TargetProcessId],

include=[ImageFileName,FileName,CommandLine,AuthenticationId]

)

| table([ComputerName, AuthenticationId, FileName, CommandLine, RegObjectName, RegValueName, RegStringValue])

tcpdump — Capture outbound shell/C2 traffic following privilege escalation:

tcpdump -i eth0 -w /captures/escalation_traffic\_%Y%m%d\_%H%M%S.pcap -G 1800 -C 200 \\
```

"not (port 1217 or port 22350 or port 443 or port 80) and (src host \<workstation-ip\>)"

Datadog Log Search — Collect privilege escalation events on engineering workstations:

```text
source:windows @evt.name:4672

// time range: last 90 days; Event ID 4672 (Special Logon) indicates SYSTEM or admin-level privilege assignment
```

Datadog Live Process Monitoring:

```text
command:CODESYS user:SYSTEM
```

Windows Event Collection — Privilege escalation indicators (Event IDs 4672, 4648, 4697):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672,4648; StartTime=(Get-Date).AddDays(-90)} |

Where-Object { $\_.Properties[1].Value -match 'codesys|codemeter|festo' } |

Select-Object TimeCreated, Id,

@{N='Account'; E={$\_.Properties[1].Value}},

@{N='Privileges';E={$\_.Properties[4].Value}} |

Export-Csv C:\hunt\codesys_priv_esc.csv -NoTypeInformation
```

\# Service installation (potential persistence post-escalation):

```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-90)} |

Select-Object TimeCreated, Message |

Export-Csv C:\hunt\new_services.csv -NoTypeInformation

YARA — Scan writable system directories for dropped tools (post-escalation):

yara -r C:\hunt\rules\post_exploitation_tools.yar C:\Windows\Temp\\ >> C:\hunt\temp_dir_yara_hits.txt

yara -r C:\hunt\rules\post_exploitation_tools.yar C:\ProgramData\\ >> C:\hunt\programdata_yara_hits.txt
```

### Analysis Queries

CrowdStrike Falcon — Detect CODESYS processes executing with SYSTEM context (CVE-2022-4046 escalation):

```powershell
#event_simpleName = "ProcessRollup2"

| FileName = /codesys/i OR ParentBaseFileName = /codesys/i

| AuthenticationId = "0x3e7"

| join(query={#event_simpleName=UserIdentity}, field=AuthenticationId, include=[UserName])

| table([ComputerName, AuthenticationId, UserName, ImageFileName, FileName, CommandLine, ParentBaseFileName])
```

CrowdStrike Falcon — OS command injection via CODESYS file system functions (CVE-2023-6357):

```text
#event_simpleName = "ProcessRollup2"

| ParentBaseFileName = /codesys/i

| in(FileName, values=["cmd.exe","powershell.exe","wscript.exe","cscript.exe","bash.exe","sh.exe"])

| table([ComputerName, ParentBaseFileName, FileName, CommandLine, AuthenticationId, ContextTimeStamp])
```

Wireshark — Detect reverse shell traffic post-exploitation:

tcp.flags.syn == 1 and not tcp.flags.ack == 1 and not (tcp.dstport == 80 or tcp.dstport == 443 or tcp.dstport == 1217 or tcp.dstport == 22350)

\# tshark — extract unexpected outbound SYNs from workstation:

```bash
tshark -r escalation_traffic.pcap \\
```

-Y "tcp.flags.syn == 1 && !tcp.flags.ack && !(tcp.dstport == 80 || tcp.dstport == 443)" \\

-T fields -e ip.src -e ip.dst -e tcp.dstport -e frame.time \>\> outbound_syns.txt

Datadog Log Analytics — Privilege escalation event frequency by host:

```text
source:windows @evt.name:4672

// Analytics: Table view; group by host; time range: last 90 days

// Flag hosts where 4672 events appear outside authorized admin session windows
```

Datadog Audit Trail — Detect API key or integration abuse following credential compromise:

```text
source:datadog @evt.category:api_key_management

// Flag new API key creation outside change management windows; time range: last 90 days
```

Datadog Monitor — Alert on CODESYS spawning a shell:

```text
Type: Log Alert

Query: source:windows "codesys" ("cmd.exe" OR "powershell.exe" OR "wscript.exe" OR "bash.exe")

Evaluation window: last 5 minutes

Alert condition: count > 0

Message: "ALERT: CODESYS spawned shell process — possible CVE-2023-6357 OS command injection — @security-oncall"
```

Prerequisites: Windows Security Event ID 4688 with command-line logging, forwarded to Datadog

Windows PowerShell Analysis — Hunt scheduled tasks created post-exploitation:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; Id=106; StartTime=(Get-Date).AddDays(-90)} |

Select-Object TimeCreated, Message |

Export-Csv C:\hunt\new_scheduled_tasks.csv -NoTypeInformation
```

\# Correlate with CODESYS process spawn timeline from 4688 CSV

Credential Access — Standing YARA rule for credential dump tooling (Windows hosts):

```text
Get-Process | ForEach-Object {

yara -p $\_.Id C:\hunt\rules\Credential_Dump_Tool_Memory_Artifacts.yar 2>>C:\hunt\yara_errors.txt

} >> C:\hunt\all_process_cred_hits.txt
```

\# Note: Credential_Dump_Tool_Memory_Artifacts rule targets Windows LSASS tooling

\# Scope to engineering workstations and Windows hosts only

3. Threat Actor Profile

Nation-state and advanced persistent threat (APT) actors targeting critical manufacturing and industrial control systems represent the highest-severity threat scenario for environments running vulnerable CODESYS deployments. Groups affiliated with China (e.g., Volt Typhoon), Russia (e.g., Sandworm), and Iran have documented histories of targeting ICS/OT environments and exploiting publicly disclosed SCADA and engineering software vulnerabilities. The multi-year window of unpatched CODESYS exposure in FAS environments represents an opportunity for pre-positioned access that may have been established long before this advisory. These actors typically seek persistent access to engineering workstations as a staging point for OT network reconnaissance and, in worst-case scenarios, disruptive or destructive actions against industrial processes. Sophistication: high. Access path: internet-exposed engineering workstations or IT/OT pivot via phishing and lateral movement. TTPs: T1190 (exploit public-facing application), T1021 (remote services), T1078 (valid accounts), T1571 (non-standard ports for C2 communication).

Opportunistic criminal actors, including ransomware operators, increasingly target industrial environments due to high-pressure operational dependencies and willingness to pay ransoms to restore production. CODESYS vulnerability disclosures are indexed by commodity threat actors who scan for exposed service ports (TCP/UDP 1217, 22350). Ransomware actors may exploit CVE-2020-14509 or CVE-2023-3935 on internet-adjacent engineering workstations as an initial access vector, followed by lateral movement to domain controllers and OT network hosts. Sophistication: medium. Access path: opportunistic internet scanning, phishing. TTPs: T1190, T1486 (data encrypted for impact), T1490 (inhibit system recovery).

Hacktivist and ideologically motivated threat actors have targeted European manufacturing and critical infrastructure. Festo's German origin and the worldwide deployment scope of affected products make this a credible threat vector for actors targeting European industrial firms or their supply chains. Access path: public-facing services, credential stuffing against VPN/RDP. Sophistication: low to medium. TTPs: T1190, T1498 (denial of service).

4. Data Sources Required

Endpoint telemetry from CrowdStrike Falcon is required on all engineering workstations with Festo Automation Suite installed, with full process tree collection, network connection logging, and file write event capture enabled. Windows Security Event Logs (Event IDs 4688, 4648, 4672, 4697, 7034, 7045) with command-line audit enabled, forwarded via Datadog Agent or SIEM connector. Windows Sysmon (Event IDs 1, 3, 7, 11) deployed on engineering workstations for process creation, network connection, driver load, and file creation logging.

Network capture (PCAP or NetFlow) on the engineering LAN uplink and the IT/OT DMZ interface, with rolling 24-hour retention. Firewall logs covering all traffic to and from TCP/UDP 1217 (CODESYS V3), TCP/UDP 22350 (Wibu CodeMeter), and TCP 8080/443 (CODESYS web server). OT network monitoring platform (Claroty, Dragos, or Nozomi) connection logs and asset inventory exports for CODESYS protocol (port 1217) traffic to PLCs and controllers.

CODESYS GatewayService application logs from C:\ProgramData\CODESYS\GatewayService\Logs\\ forwarded via custom Datadog Agent log collection or aggregated via a SIEM. Process historian (OSIsoft PI, Emerson DeltaV, Wonderware) alarm and event logs for correlation of anomalous controller behavior with workstation-level compromise indicators. SNMP interface counters from access switches in the engineering LAN for bandwidth anomaly detection.

5. Detection Signatures

The following SIGMA rule detects unexpected process creation with CODESYS runtime components as the parent process, targeting engineering workstations where CODESYS Development System or Festo Automation Suite is installed. This rule targets OS command injection (CVE-2023-6357) and post-exploitation shell spawning following web server exploitation (CVE-2019-13548, CVE-2020-10245). The condition filters specifically for shell and scripting interpreter children of known CODESYS process names, minimizing false positives from legitimate CODESYS toolchain processes that spawn compilers or linkers.

```yaml
title: CODESYS Runtime Spawns Shell or Scripting Interpreter

id: 3a7f1b2e-d5c4-4e8a-b91f-06a3d72c40e9

status: experimental

description: >
```

Detects a shell or scripting interpreter process spawned by a CODESYS

runtime or service process, which may indicate exploitation of CVE-2019-13548,

CVE-2020-10245, CVE-2021-33485, or CVE-2023-6357 in Festo Automation Suite.

```yaml
references:
```

\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-076-01

\- https://nvd.nist.gov/vuln/detail/CVE-2023-6357

```yaml
author: 1898 & Co. Threat Intelligence

date: 2026-03-23

tags:
```

\- attack.initial_access

\- attack.t1190

\- attack.privilege_escalation

\- attack.t1068

```yaml
logsource:
```

category: process_creation

product: windows

```yaml
detection:
```

selection_parent:

ParentImage|contains:

\- 'CoDeSysControlWinSysService'

\- 'codesyscontrol'

\- 'CODESYS'

\- 'GatewayService'

selection_child:

Image|endswith:

\- '\cmd.exe'

\- '\powershell.exe'

\- '\wscript.exe'

\- '\cscript.exe'

\- '\mshta.exe'

\- '\bash.exe'

\- '\sh.exe'

\- '\rundll32.exe'

\- '\regsvr32.exe'

```yaml
condition: selection_parent and selection_child

falsepositives:
```

\- Legitimate CODESYS build scripts invoking cmd.exe during compilation (baseline known build systems)

\- Automated test harnesses running shell commands via CODESYS scripting engine

```yaml
level: high
```

The following SIGMA rule detects network connections to Wibu CodeMeter daemon port 22350 from external or unexpected source IP addresses, targeting opportunistic exploitation of CVE-2020-14509 and CVE-2023-3935. The rule uses a network connection logsource to catch Sysmon Event ID 3 or equivalent EDR telemetry. The condition is structured as a destination port match with a NOT filter for known internal subnets, reducing false positives from legitimate inter-workstation CodeMeter license checks while flagging connections from unexpected network ranges.

```yaml
title: Wibu CodeMeter Daemon Inbound Connection from Unexpected Source

id: 9c4d2a7f-e1b3-4f5a-8d0e-12c3b74a91f5

status: experimental

description: >
```

Detects inbound network connections to the Wibu CodeMeter daemon (TCP/UDP 22350)

from source IPs outside the authorized engineering workstation subnet. May indicate

exploitation of CVE-2020-14509 or CVE-2023-3935 from a network-adjacent attacker.

```yaml
references:
```

\- https://nvd.nist.gov/vuln/detail/CVE-2020-14509

\- https://nvd.nist.gov/vuln/detail/CVE-2023-3935

```yaml
author: 1898 & Co. Threat Intelligence

date: 2026-03-23

tags:
```

\- attack.initial_access

\- attack.t1190

```yaml
logsource:
```

category: network_connection

product: windows

```yaml
detection:

selection:
```

DestinationPort: 22350

filter_authorized:

SourceIp|cidr:

\- '10.0.0.0/8'

\- '172.16.0.0/12'

\- '192.168.0.0/16'

```yaml
condition: selection and not filter_authorized

falsepositives:
```

\- CodeMeter license server reachable from cloud or VPN NAT addresses — baseline known external license server IPs

```yaml
level: high
```

The following SIGMA rule targets DNS resolution of CODESYS or CodeMeter domains with non-vendor FQDN patterns, detecting post-exploitation C2 beaconing. The condition uses a substring match against CODESYS/Wibu brand strings combined with a NOT filter for the legitimate vendor FQDNs, so that only suspicious non-vendor domains containing the brand strings as substrings trigger the rule.

```yaml
title: CODESYS Engineering Workstation DNS Lookup for Non-Vendor Domain

id: b2e8c3d1-7a4f-4b6e-9f1a-53d2e80c74b6

status: experimental

description: >
```

Detects DNS resolution of domains containing CODESYS or Wibu brand strings

but not resolving to the legitimate vendor domains, used to detect post-exploitation

C2 beaconing via typosquatted or attacker-controlled domains.

```yaml
references:
```

\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-076-01

```yaml
author: 1898 & Co. Threat Intelligence

date: 2026-03-23

tags:
```

\- attack.command_and_control

\- attack.t1071

```yaml
logsource:
```

category: dns_query

product: windows

```yaml
detection:

selection:
```

QueryName|contains:

\- 'codesys'

\- 'wibu'

\- 'codemeter'

filter_legitimate:

QueryName|endswith:

\- '.codesys.com'

\- '.wibu.com'

```yaml
condition: selection and not filter_legitimate

falsepositives:
```

\- Internal DNS zones using codesys or wibu as subdomain fragments

\- Typo-squatted domains triggering on substring — review full FQDN before escalating

```yaml
level: medium
```

Snort/Suricata rule to detect oversized packets to the Wibu CodeMeter daemon, targeting exploitation of the length field validation failure in CVE-2020-14509. The threshold suppresses single-packet anomalies and requires a burst pattern consistent with exploitation attempts.

```text
alert udp any any -> $HOME_NET 22350 (
```

msg:"CODESYS Wibu CodeMeter Oversized UDP Packet - Possible CVE-2020-14509 Exploitation";

dsize:\>1400;

threshold:type both, track by_src, count 3, seconds 60;

classtype:attempted-admin;

sid:9100001;

rev:1;

reference:cve,2020-14509;

reference:url,nvd.nist.gov/vuln/detail/CVE-2020-14509;

metadata:affected_product CODESYS_CodeMeter, deployment ICS, created_at 2026-03-23;

)

Snort/Suricata rule to detect TCP connections to the CODESYS V3 runtime port from hosts not in the authorized engineering subnet, targeting lateral movement via CVE-2019-9010 gateway hijacking.

```text
alert tcp !$ENGINEERING_NET any -> $OT_NET 1217 (
```

msg:"CODESYS V3 Runtime Connection from Non-Engineering Host - Possible CVE-2019-9010 Gateway Abuse";

flags:S;

threshold:type both, track by_src, count 1, seconds 1;

classtype:policy-violation;

sid:9100002;

rev:1;

reference:cve,2019-9010;

reference:url,nvd.nist.gov/vuln/detail/CVE-2019-9010;

metadata:affected_product CODESYS_CmpGateway, deployment ICS, created_at 2026-03-23;

)

The first YARA rule targets dropped exploit artifacts and post-exploitation tools in the CODESYS installation directory and Windows temporary paths. This rule targets file-system artifacts because successful exploitation of the web server or CodeMeter buffer overflow vulnerabilities commonly results in a dropped second-stage payload or persistence mechanism written to a writable directory on the compromised workstation. The condition requires both a file-system path indicator and at least one known attacker tool string, reducing false positives from legitimate administrative tools.

```yara
rule CODESYS_Exploit_Artifacts_on_Disk
```

{

meta:

description = "Detects post-exploitation artifacts dropped on disk following CODESYS or CodeMeter exploitation — targets second-stage payloads and attacker tools written to CODESYS or temp directories"

author = "1898 & Co. Threat Intelligence"

date = "2026-03-23"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-076-01"

strings:

\$path_codesys = "CODESYS" wide ascii nocase

\$path_gw = "GatewayService" wide ascii

\$tool_mimi = "sekurlsa::logonpasswords" wide ascii

\$tool_cs = { 4D 53 46 21 00 00 00 00 }

\$tool_empire = "Empire" wide ascii

\$tool_meterp = "meterpreter" wide ascii nocase

\$tool_revshell = /cmd\\exe.\*\\c.\*powershell.\*\\\[Ee\]nc/ wide ascii

condition:

(any of (\$path\_\*)) and (any of (\$tool\_\*))

}

// File-system scan:

// yara -r C:\hunt\rules\CODESYS_Exploit_Artifacts_on_Disk.yar "C:\Program Files\CODESYS\\ "C:\Windows\Temp\\ "C:\ProgramData\\ \>\> C:\hunt\disk_yara_hits.txt

The second YARA rule targets in-memory post-exploitation and credential dumping artifacts. This rule covers the standing Credential_Dump_Tool_Memory_Artifacts requirement for any hunt involving privilege escalation. The condition uses OR branches across four distinct tool families so that any single branch constitutes a hit, plus a fifth catch-all branch. Note: this rule targets Windows LSASS tooling; scope to engineering workstations and Windows hosts only.

```yara
rule Credential_Dump_Tool_Memory_Artifacts
```

{

meta:

description = "Detects in-memory artifacts of credential dumping tools — covers mimikatz, WCE, gsecdump, and comsvcs MiniDump; requires SeDebugPrivilege to run against LSASS"

author = "1898 & Co. Threat Intelligence"

date = "2026-03-23"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-076-01"

note = "Windows-only rule; scope to engineering workstations and Windows runner pools"

strings:

\$mimi_1 = "sekurlsa::logonpasswords" wide ascii

\$mimi_2 = "lsadump::sam" wide ascii

\$mimi_3 = "privilege::debug" wide ascii

\$mimi_4 = "mimikatz" wide ascii nocase

\$mimi_h = { 6D 69 6D 69 6B 61 74 7A }

\$wce_1 = "wce.exe" wide ascii

\$wce_2 = "lsass.exe" wide ascii

\$gsec = "gsecdump" wide ascii nocase

\$mini_1 = "MiniDump" wide ascii

\$mini_2 = "comsvcs" wide ascii

\$mini_3 = "lsass.exe" wide ascii

\$api_1 = "NtReadVirtualMemory" wide ascii

\$api_2 = "ReadProcessMemory" wide ascii

\$lsass = "lsass.exe" wide ascii

condition:

(2 of (\$mimi\_\*)) or

(all of (\$wce\_\*)) or

(\$gsec) or

(all of (\$mini\_\*)) or

(1 of (\$api\_\*) and \$lsass)

}

// Memory scan (requires admin/SeDebugPrivilege):

// Get-Process | ForEach-Object { yara -p $_.Id C:\hunt\rules\Credential_Dump_Tool_Memory_Artifacts.yar } \>\> C:\hunt\cred_dump_memory_hits.txt

// CrowdStrike RTR: Run-Script -CloudFile cred_dump_yara.ps1 -HostIds \<target_aid\>

6. Indicators of Compromise

Network IOCs: No specific attacker-controlled IP addresses or C2 domains have been published in the CISA advisory or VDE disclosure. Analysts should treat any inbound connections to TCP/UDP 22350 (Wibu CodeMeter) and TCP 8080 (CODESYS web server) from IPs outside the authorized engineering workstation subnet as anomalous. Outbound connections from CODESYS processes to non-CODESYS update domains or to IP addresses not associated with licensed controller assets should be investigated. Relevant ports to monitor: TCP/UDP 1217 (CODESYS V3), TCP/UDP 22350 (Wibu CodeMeter), TCP 8080 (CODESYS web server), TCP 4840 (OPC-UA).

Host IOCs: Behavioral indicators include unexpected child processes spawned by CoDeSysControlWinSysService64.exe, codesyscontrol.exe, or CodeMeter.exe; executables or scripts dropped to C:\Windows\Temp\\ C:\ProgramData\\ or the CODESYS installation directory by CODESYS-related processes; new Windows services installed outside change management windows; and CODESYS process memory containing credential dumping tool artifacts. Windows Event ID 4688 records of cmd.exe or powershell.exe with CODESYS parent processes are high-confidence indicators.

OT/Operational IOCs: Unexpected CODESYS gateway connections to PLC IP addresses outside authorized engineering session windows; EtherNet/IP CIP Write Tag (service code 0x4d) commands from an engineering workstation IP outside maintenance windows; process variable changes in the historian attributed to the engineering workstation IP outside authorized change windows; and controller alarms for "communication lost" correlating with CodeMeter service crash timestamps.

7. False Positive Baseline

Legitimate CODESYS Development System compilation and deployment sessions will generate outbound TCP 1217 connections from engineering workstations to PLC IP addresses during authorized programming sessions — compare against the change management schedule before escalation.

CodeMeter license heartbeat traffic on UDP/TCP 22350 between engineering workstations sharing a network license server is expected and should be baselined against the authorized workstation IP list.

CODESYS GatewayService writes log files to C:\ProgramData\CODESYS\GatewayService\Logs\\ during normal operation — file write events from GatewayService.exe to this path are expected.

Antivirus or endpoint protection software scanning the CODESYS installation directory may generate elevated process creation activity under the CODESYS parent process hierarchy — confirm scanner PID and executable path before escalating.

CODESYS automatic update checks will generate DNS queries for update.codesys.com and HTTP/HTTPS connections to codesys.com — whitelist these in DNS and firewall monitoring queries to reduce false positive volume.

8. Escalation Criteria

Escalate to Incident Response immediately upon observing any of the following:

1. A shell or scripting interpreter (cmd.exe, powershell.exe, wscript.exe, bash.exe) confirmed as a child process of a CODESYS runtime or service process in CrowdStrike Falcon telemetry or Windows Event ID 4688 logs.

2. A new executable written by a CODESYS-related process to C:\Windows\Temp\\ C:\Windows\System32\\ or C:\ProgramData\\ outside of a known software update window.

3. Any YARA hit from the rule CODESYS_Exploit_Artifacts_on_Disk against any file path under the CODESYS installation directory, Windows Temp, or ProgramData.

4. Any YARA hit from the rule Credential_Dump_Tool_Memory_Artifacts against any process on an engineering workstation.

5. Any inbound TCP or UDP connection to port 22350 (Wibu CodeMeter) from a source IP address outside the authorized engineering workstation subnet, confirmed in firewall logs or Sysmon Event ID 3.

6. A CODESYS gateway connection to a PLC or controller IP address not present in the authorized asset inventory and not scheduled in the change management log.

7. Any EtherNet/IP CIP Write Tag command originating from an engineering workstation IP address outside an authorized maintenance window, confirmed in PCAP or OT monitoring platform logs.

8. Any Datadog Monitor alert defined in Section 2 firing with a confirmed match — treat all Section 2 monitor alerts as requiring immediate triage.

9. Hunt Completion Criteria and Reporting

The hunt is complete when all four hypotheses have been fully investigated across the defined host and network scope, all YARA file-system and memory scans have completed without unresolved hits, and all anomalous network connections identified during collection have been attributed to either a known-good baseline source or a confirmed incident. If access to a required data source is unavailable, document the gap explicitly in the final report and provide compensating detection logic.

The hunt report must contain: a summary of all CODESYS and CodeMeter versions found across the engineering workstation inventory with patch status against the remediated versions in VDE-2025-108; a record of all anomalous process creation events reviewed and their disposition; a log of all network connections to CODESYS and CodeMeter ports with source/destination attribution; PCAP-based confirmation or refutation of the Hypothesis 2 CodeMeter oversized packet pattern; OT gateway connection log analysis results against the authorized PLC asset inventory; and all YARA scan results including any hits and their resolution. Per Section 8, Escalation Criteria item 3 requires that any YARA hit on CODESYS_Exploit_Artifacts_on_Disk triggers IR engagement before the hunt is closed. Item 4 requires the same immediate escalation for any Credential_Dump_Tool_Memory_Artifacts hit across any process on scoped workstations.

10\. Advisory IoC Reference

| IOC Type | IOC |
|----|----|
| CVE | CVE-2018-10612 | CVSS v3.0 9.8 | CODESYS Control V3 \< 3.5.14.0 | User access management and communication encryption disabled by default; unauthenticated network access to credentials and runtime communications |
| CVE | CVE-2019-9010 | CVSS v3.1 9.8 | CODESYS CmpGateway V3 \< 3.5.14.20 | Gateway communication channel ownership verification failure; allows unauthenticated channel hijacking and pivot to downstream PLCs |
| CVE | CVE-2019-13548 | CVSS v3.1 9.8 | CODESYS V3 Web Server \< 3.5.14.10 | Stack-based buffer overflow via crafted HTTP/HTTPS requests; unauthenticated remote code execution or DoS |
| CVE | CVE-2019-18858 | CVSS v3.1 9.8 | CODESYS V3 Web Server \< 3.5.15.20 | Buffer overflow in web server component; unauthenticated remote code execution |
| CVE | CVE-2020-10245 | CVSS v3.1 9.8 | CODESYS V3 Web Server \< 3.5.15.40 | Out-of-bounds write in web server; unauthenticated remote code execution |
| CVE | CVE-2020-14509 | CVSS v3.1 9.8 | Wibu CodeMeter \< 7.10 | Packet parser does not verify length fields; memory corruption and unauthenticated RCE via crafted packets to port 22350 |
| CVE | CVE-2020-14517 | CVSS v3.1 9.8 | Wibu CodeMeter \< 7.10 | Broken and weak cryptographic algorithms in CodeMeter; remote interception and manipulation of license management communications |
| CVE | CVE-2021-33485 | CVSS v3.1 9.8 | CODESYS Control Runtime | Heap-based buffer overflow; unauthenticated remote code execution via crafted network packets |
| CVE | CVE-2022-4046 | CVSS v3.1 8.8 | CODESYS V3 Runtime | Authenticated low-privilege remote buffer overflow; full device access |
| CVE | CVE-2023-3935 | CVSS v3.1 9.8 | Wibu CodeMeter Runtime \< 7.60c | Heap buffer overflow; unauthenticated remote code execution |
| CVE | CVE-2023-6357 | CVSS v3.1 8.8 | CODESYS V3 File System Libraries | OS command injection via file system library functions; low-privilege remote command execution |
| CVE | CVE-2025-2595 | CVSS v3.1 5.3 | CODESYS Visualization | Forced browsing (CWE-425) allows unauthenticated access to visualization template files and static elements |
| Threat Actor | None published in source material — monitor CISA ICS-CERT and CERT@VDE for threat actor attribution as exploitation is observed |
| Malware | None published in source material — no specific malware families attributed to exploitation of these vulnerabilities at time of advisory |
| Network IOC | None published in source material — monitor CISA ICS-CERT feed for attacker infrastructure indicators; flag inbound connections to TCP/UDP 22350 and TCP 8080 from non-engineering subnet IPs |
| File IOC | None published in source material — monitor for executables dropped to C:\Windows\Temp\\ or C:\ProgramData\\ by CODESYS or CodeMeter processes |
| Behavioral | CODESYS runtime (CoDeSysControlWinSysService64.exe) spawning cmd.exe, powershell.exe, or wscript.exe as child process |
| Behavioral | CodeMeter.exe (Wibu CodeMeter daemon) spawning unexpected child processes or crashing repeatedly within a short time window |
| Behavioral | Inbound TCP/UDP connections to port 22350 (CodeMeter) from source IPs outside the authorized engineering workstation subnet |
| Behavioral | CODESYS gateway (GatewayService.exe) establishing TCP 1217 connections to PLC IP addresses not in the authorized asset inventory |
| Behavioral | EtherNet/IP CIP Write Tag (service code 0x4d) commands from engineering workstation IP outside authorized maintenance window |
| Behavioral | Windows Event ID 4688 recording shell process spawned with CODESYS process as parent (command-line audit required) |
| Behavioral | New Windows service (Event ID 7045) installed on engineering workstation outside change management window |
