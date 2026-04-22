# Threat Hunt Plan: CVE-2025-49844 / CVE-2025-46817 / CVE-2025-46818 / CVE-2025-46819 — Schneider Electric Plant iT/Brewmaxx Redis Lua Engine RCE

Revision 1.0 | 27 March 2026

# Hunt Objective and Scope

The objective of this hunt is to detect active or historical exploitation of four Redis Lua engine vulnerabilities (CVE-2025-49844, CVE-2025-46817, CVE-2025-46818, CVE-2025-46819) within Schneider Electric Plant iT/Brewmaxx deployments. Huntable artifacts include anomalous process execution chains originating from the redis-server.exe process, unauthorized Redis EVAL or FUNCTION LOAD command usage in command logs, unexpected outbound network connections from application servers hosting Plant iT/Brewmaxx, and Redis service crash events consistent with CVE-2025-46819 exploitation. The environment in scope includes all Windows application servers running Plant iT/Brewmaxx version 9.60 or above, VisuHub visualization servers, engineering workstations with Redis installed, and connected OT network segments reachable from the application tier. The recommended hunt window spans the 90 days prior to ProLeiT-2025-001 patch application or back to October 3, 2025 (the CVE public disclosure date), whichever is more recent. Prioritize assets where Redis port TCP 6379 is accessible from corporate networks, DMZ segments, or any externally reachable zone.

# Hypotheses and Hunt Procedures

## Hypothesis 1

An attacker has exploited CVE-2025-49844 (RediShell use-after-free) or CVE-2025-46817 (integer overflow) to achieve remote code execution via a crafted Lua script submitted to the Redis EVAL command, observable as anomalous child processes spawned by redis-server.exe in Windows process creation telemetry.

### MITRE ATT&CK

Execution | T1190 — Exploit Public-Facing Application | Redis is network-accessible and processes unauthenticated or minimally authenticated Lua scripts, making it a directly exploitable application entry point consistent with T1190 for environments where Redis is exposed beyond localhost.

### Collection Queries

#### CrowdStrike Falcon FQL — Process creation under Redis service (collect all child processes)

```text
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = /redis-server/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, AuthenticationId])
#### CrowdStrike Falcon FQL — Redis spawning known post-exploitation interpreters
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = /redis-server/i
| FileName = /^(cmd\\exe|powershell\\exe|wscript\\exe|cscript\\exe|mshta\\exe|certutil\\exe|bitsadmin\\exe|rundll32\\exe|regsvr32\\exe|wmic\\exe|net\\exe|net1\\exe)$/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, AuthenticationId])
#### CrowdStrike Falcon FQL — New executables written to disk by Redis service account
#event_simpleName = "NewExecutableWritten"
| TargetFileName = /redis/i
| table([ComputerName, TargetFileName, FilePath, ContextProcessId])
```

#### tcpdump — Capture all TCP/6379 traffic to Redis application server (rolling hourly files)

```text
tcpdump -i eth0 -w /captures/redis\_%Y%m%d\_%H%M.pcap -G 3600 -C 500 "tcp port 6379"
#### tcpdump — Host-scoped rolling capture for Redis server IP
tcpdump -i eth0 -w /captures/redis_host\_%Y%m%d\_%H%M.pcap -G 1800 -C 200 "host <redis_server_ip> and tcp port 6379"
```

#### Datadog Log Search — Windows process creation under Redis (EventID 4688)

```text
source:windows @EventID:4688 @ParentProcessName:"redis-server.exe"
// time range: 90 days prior to patch date to current
#### Datadog Log Search — All redis-server.exe process creation events for baseline
source:windows @EventID:4688 message:"redis-server.exe"
// time range: hunt window; collect for process tree analysis
```
#### Datadog Live Process Monitoring — Verify Redis service account and command line

```text
command:redis-server
// Infrastructure \> Processes; flag any redis-server.exe not running as expected NT SERVICE account
```

#### Windows Event IDs to collect

Event ID 4688 (Process Creation with command line auditing): capture on all Plant iT application servers; filter for ParentProcessName = redis-server.exe; requires Audit Process Creation policy and Include command line in process creation events registry key enabled

Event ID 4624 (Logon): collect all network logon events (LogonType 3) to application servers during hunt window; baseline against normal service account activity

Event ID 7034 (Service Crashed Unexpectedly): collect from System log for Redis service crashes consistent with memory corruption or CVE-2025-46819 DoS activity

#### PowerShell — Collect process creation events with redis-server.exe as parent

```text
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=(Get-Date).AddDays(-90)} |
Where-Object {$\_.Message -match 'redis-server'} |
Select-Object TimeCreated,
@{N='NewProcess';E={$\_.Properties[5].Value}},
@{N='CommandLine';E={$\_.Properties[8].Value}},
@{N='ParentProcess';E={$\_.Properties[13].Value}} |
Export-Csv -Path C:\hunt\redis_proc_creation.csv -NoTypeInformation
```

#### OT Data Collection: Claroty CTD — Administration \> Reports \> Connection Activity, filter Source or Destination IP = Plant iT application server IP, date range = hunt window, export CSV; flag new connections to PLC or HMI IP ranges originating from the application server tier

#### OT Data Collection: Dragos Platform — Investigate \> Connection Timeline, filter IP = application server; Detections panel Category = Exploitation or Command and Control for alert-driven collection of post-exploitation indicators

#### OT Data Collection: Nozomi Networks — Assets \> Connections, filter Source IP = application server IP, export via GET /api/open/connections?src_ip=\<app_server_ip\>; review for unexpected protocol connections to OT device ranges

#### OT Data Collection: Armis — Asset Management \> Devices \> filter IP = application server; review Policy violations for anomalous outbound connections; REST API: GET /api/v1/devices?ip=\<app_server_ip\>

#### OT Data Collection: Tenable OT — Assets \> Devices \> Export; Vulnerabilities view filtered to application server for CVE-2025-49844 detection status; REST API: GET /api/v1/events?asset_ip=\<app_server_ip\>

#### OT Data Collection: Forescout eyeInspect — Inventory \> Devices \> filter application server IP; Threat Detection panel for anomalous lateral connections; GET /api/v1/connections?src=\<app_server_ip\>

#### YARA file-system scan — Redis working directory and Windows Temp for exploit staging artifacts

```text
yara -r redis_lua_rce.yar C:\ProgramData\Redis\\ >> C:\hunt\yara_redis_hits.txt
yara -r redis_lua_rce.yar C:\Windows\Temp\\ >> C:\hunt\yara_redis_hits.txt
yara -r redis_lua_rce.yar "C:\Program Files\Redis\\ >> C:\hunt\yara_redis_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Rarity: uncommon child processes of redis-server.exe (rarest first)
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = /redis-server/i
| groupBy([ComputerName, FileName, CommandLine], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
#### CrowdStrike Falcon FQL — Outbound network connections from Redis process to non-Redis ports (Template C)
#event_simpleName = "NetworkConnectIP4"
| RemotePort != 6379
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]
)
| FileName = /redis-server/i
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName])
```

#### Wireshark display filter — Redis EVAL command payload inspection

tcp.port == 6379 && tcp.payload contains "EVAL"

#### Wireshark display filter — Large Redis responses (potential bulk data exfiltration)

tcp.port == 6379 && tcp.len \> 65535

#### tshark CLI — Extract all EVAL command flows from capture for payload review

```text
tshark -r /captures/redis_capture.pcap -Y 'tcp.port==6379 && tcp.payload contains "EVAL"' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.payload -E separator=, > C:\hunt\redis_eval_commands.csv
#### tshark CLI — Extract all Redis commands for full command log reconstruction
tshark -r /captures/redis_capture.pcap -Y 'tcp.port==6379 && tcp.flags.push==1' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.payload -E separator=, > C:\hunt\redis_all_commands.csv
```

#### Datadog Log Analytics — Child process frequency under Redis (Top List)

```text
source:windows @EventID:4688 @ParentProcessName:"redis-server.exe"
// Analytics: Top List view, group by @NewProcessName; time range: hunt window; sort ascending for rarest first
```
#### Datadog Audit Trail — Administrative access to Datadog agents on Plant iT servers

```text
source:datadog @evt.category:user_access @evt.name:login
// time range: hunt window; flag logins from unexpected source IPs to Datadog agents on application servers
#### Datadog CloudTrail — Anomalous cloud API calls from application server IP (if cloud-connected)
source:cloudtrail @evt.name:(AssumeRole OR GetSecretValue OR DescribeInstances) -@network.client.ip:10.\* -@network.client.ip:172.16.\*
// Analytics: Table view, group by @network.client.ip, @userIdentity.arn; time range: hunt window
```

#### Windows Event Log PowerShell — Redis service crash history across hunt window

```text
Get-WinEvent -FilterHashtable @{LogName='System';Id=7034;StartTime=(Get-Date).AddDays(-90)} |
Where-Object {$\_.Message -match 'Redis'} |
Select-Object TimeCreated, Message |
Export-Csv -Path C:\hunt\redis_service_crashes.csv -NoTypeInformation
#### Windows Event Log PowerShell — Scheduled tasks created on application servers post-exploitation check
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4698;StartTime=(Get-Date).AddDays(-90)} |
Select-Object TimeCreated,
@{N='TaskName';E={$\_.Properties[0].Value}},
@{N='TaskContent';E={$\_.Properties[1].Value}} |
Export-Csv -Path C:\hunt\scheduled_tasks.csv -NoTypeInformation
```

#### OT network analysis — Modbus write function code baseline deviation (Plant iT PLC traffic)

```text
tshark -r /captures/ot_segment.pcap -Y 'mbtcp.modbus.func_code == 16 || mbtcp.modbus.func_code == 6' -T fields -e ip.src -e ip.dst -e mbtcp.modbus.func_code -e mbtcp.modbus.reference_num | sort | uniq -c | sort -rn > C:\hunt\modbus_writes.txt
```

#### Datadog Monitor — Redis spawning child process

```text
Type: Log Alert
Query: source:windows @EventID:4688 @ParentProcessName:"redis-server.exe"
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: redis-server.exe spawned child process {{@NewProcessName}} on {{host.name}} — possible CVE-2025-49844/CVE-2025-46817 exploitation. Immediate investigation required. @security-oncall"
Prerequisites: Windows Security Event Log (EventID 4688 with command line auditing) forwarded to Datadog from all Plant iT application servers; Audit Process Creation group policy and command line logging registry key enabled on all in-scope hosts
```
Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### YARA memory scan — Redis process memory for active Lua RCE artifacts

\$pid = (Get-Process redis-server | Select-Object -ExpandProperty Id -First 1)

```text
yara redis_lua_rce.yar $pid >> C:\hunt\yara_redis_mem_hits.txt
// CrowdStrike RTR: runscript -Raw=\`$p=(Get-Process redis-server -ErrorAction SilentlyContinue); if($p){yara redis_lua_rce.yar $p.Id}\` -HostIds=<agent_id>
```

## Hypothesis 2

An attacker who obtained code execution on the Plant iT application server via Redis exploitation has performed lateral movement to connected OT components or engineering workstations, observable as new SMB, RDP, or WinRM connections from the Redis service host to OT network IP ranges.

### MITRE ATT&CK

Lateral Movement | T1021.001 — Remote Services: Remote Desktop Protocol | Attackers with RCE on the application server commonly leverage RDP (TCP 3389), SMB (TCP 445), or WinRM (TCP 5985/5986) to pivot to engineering workstations and HMIs that share network adjacency with the Plant iT platform.

### Collection Queries

#### CrowdStrike Falcon FQL — Lateral movement connections from application server (Template C)

```text
#event_simpleName = "NetworkConnectIP4"
| in(RemotePort, values=["445","3389","135","5985","5986"])
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]
)
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName])
#### CrowdStrike Falcon FQL — Credential access: suspicious process accessing LSASS
#event_simpleName = "ProcessRollup2"
| FileName = /^(mimikatz|wce|gsecdump|procdump)$/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, AuthenticationId])
```

#### tcpdump — Capture lateral movement traffic from application server to OT/engineering hosts

```text
tcpdump -i eth0 -w /captures/lateral\_%Y%m%d\_%H%M.pcap -G 3600 -C 500 "src host <app_server_ip> and (dst port 445 or dst port 3389 or dst port 5985 or dst port 5986)"
```

#### Datadog Log Search — Network logon events originating from application server

```text
source:windows @EventID:4624 @LogonType:3 host:<app_server_hostname>
// time range: hunt window; review TargetComputer for OT-segment hostnames
#### Datadog Log Search — RemoteInteractive (RDP) logon events
source:windows @EventID:4624 @LogonType:10 host:<app_server_hostname>
// time range: hunt window; flag any RDP logon to engineering workstations or HMIs
```
#### Windows Event IDs to collect

Event ID 4624 (Logon) with LogonType 3 (Network) or 10 (RemoteInteractive) from application server hosts during hunt window

Event ID 4648 (Logon with explicit credentials): indicates pass-the-hash or credential reuse for lateral movement from compromised host

Event ID 4776 (NTLM Credential Validation): collect from domain controllers for NTLM authentication originating from Plant iT application servers to OT hosts

#### PowerShell — Lateral movement logon collection from application server Security log

```text
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddDays(-90)} |
Where-Object {($\_.Properties[8].Value -eq 3 -or $\_.Properties[8].Value -eq 10) -and $\_.Properties[18].Value -ne '-'} |
Select-Object TimeCreated,
@{N='LogonType';E={$\_.Properties[8].Value}},
@{N='AccountName';E={$\_.Properties[5].Value}},
@{N='SourceIP';E={$\_.Properties[18].Value}},
@{N='TargetHost';E={$\_.Properties[11].Value}} |
Export-Csv -Path C:\hunt\lateral_logons.csv -NoTypeInformation
```

#### OT Data Collection: Claroty CTD — Administration \> Reports \> Connection Activity, filter Source = application server subnet, Protocol = Modbus or EtherNet/IP or OPC-UA, date range = hunt window, export CSV; flag IT-tier to PLC/RTU/HMI connections

#### OT Data Collection: Dragos Platform — Investigate \> Connection Timeline, filter Source IP = application server range; Detections panel Category = Lateral Movement for cross-zone traversal alerts

#### OT Data Collection: Nozomi Networks — Assets \> Connections, filter Source IP = application server subnet, export via GET /api/open/connections?src_ip=\<app_server_subnet\>; review OT devices receiving unexpected inbound connections from IT tier

#### OT Data Collection: Armis — Asset Management \> Devices \> filter to OT/ICS device type; check Policy violations for devices receiving connections from application server IP; REST API: GET /api/v1/devices?type=OT

#### OT Data Collection: Tenable OT — Assets \> Devices \> Export for OT segment; REST API: GET /api/v1/events?severity=high; review for anomalous connection events to PLCs during hunt window

#### OT Data Collection: Forescout eyeInspect — Inventory \> Devices \> filter OT segment; Threat Detection panel for cross-zone traversal alerts; GET /api/v1/connections?dst_segment=OT

#### YARA file-system scan — Credential dumping tool artifacts on application server

```text
yara -r cred_dump_tools.yar C:\Windows\Temp\\ >> C:\hunt\yara_cred_hits.txt
yara -r cred_dump_tools.yar C:\Users\\ >> C:\hunt\yara_cred_hits.txt
yara -r cred_dump_tools.yar C:\ProgramData\\ >> C:\hunt\yara_cred_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Frequency: hosts initiating connections to OT subnet (rarity analysis)
#event_simpleName = "NetworkConnectIP4"
| cidr(RemoteAddressIP4, subnet=["<ot_subnet>/24"])
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,ComputerName]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,ComputerName]
)
| groupBy([ComputerName, FileName, RemoteAddressIP4], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
```

#### Wireshark display filter — SMB lateral movement to OT or engineering segment

smb2 && ip.dst == \<ot_server_ip\> && smb2.cmd == 0x0005

#### Wireshark display filter — OPC-UA session establishment baseline (Plant iT normal traffic)

opcua && tcp.port == 4840

#### tshark CLI — Extract SMB2 session setup attempts toward OT segment

```text
tshark -r /captures/lateral_capture.pcap -Y 'smb2.cmd == 0x0001 and ip.dst contains "<ot_subnet>"' -T fields -e ip.src -e ip.dst -e smb2.ses_id -E separator=, > C:\hunt\smb_lateral.csv
```

#### Datadog Log Analytics — Network logon frequency by source and target host

```text
source:windows @EventID:4624 @LogonType:3
// Analytics: Table view, group by host, @TargetComputer; time range: hunt window
// Flag hosts in application server subnet with elevated logon counts to OT segment
```
#### OT network analysis — EtherNet/IP CIP service code anomalies from IT tier

```text
tshark -r /captures/ot_segment.pcap -Y 'enip && ip.src == <app_server_ip>' -T fields -e ip.src -e ip.dst -e cip.service | sort | uniq -c | sort -rn > C:\hunt\enip_from_it.txt
```

#### Datadog Monitor — Network logon from application server to OT hosts

```text
Type: Log Alert
Query: source:windows @EventID:4624 @LogonType:3 @TargetComputer:(<ot_hostname_1> OR <ot_hostname_2>)
Evaluation window: last 15 minutes
Alert condition: count > 0
Message: "ALERT: Network logon from {{host.name}} to OT host {{@TargetComputer}} — potential lateral movement following Redis exploitation. @security-oncall @ot-security-team"
Prerequisites: Windows Security Event Log (ID 4624) forwarded from all Plant iT application servers; OT Windows hosts must have Datadog Agent installed and Security Event Log forwarding enabled
```
Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### YARA memory scan — Credential dumping tools in memory of all application server processes

```text
Get-Process | ForEach-Object {
```

\$result = yara cred_dump_tools.yar $_.Id 2\>\$null

if (\$result) { Write-Output "HIT PID=\$($_.Id) Name=\$($_.ProcessName): \$result" }

} \>\> C:\hunt\yara_cred_mem_hits.txt

// CrowdStrike RTR: runscript -Raw=\`Get-Process | ForEach-Object { yara cred_dump_tools.yar $_.Id 2\>\$null }\` -HostIds=\<agent_id\>

## Hypothesis 3

An attacker has exploited CVE-2025-46818 (code injection) to execute Redis commands in the context of a privileged Redis user account, manipulating process historian data stored in Redis, observable as unauthorized SET, HSET, or DEL commands against historian keys in Redis command logs and anomalous value deviations in Plant iT process historian tables.

### MITRE ATT&CK

Impact | T1565.001 — Data Manipulation: Stored Data Manipulation | Redis serves as the real-time data store for Plant iT/Brewmaxx process values and batch recipe data; unauthorized key-value manipulation constitutes stored data manipulation with direct process integrity implications.

### Collection Queries

#### CrowdStrike Falcon FQL — Redis configuration registry modifications (Template B)

```text
#event_simpleName = "RegGenericValueUpdate"
| RegObjectName = /redis/i
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId]), limit=100000)},
field=[aid,ContextProcessId], key=[aid,TargetProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId]
)
| table([ComputerName, AuthenticationId, FileName, CommandLine, RegObjectName, RegValueName, RegStringValue])
#### CrowdStrike Falcon FQL — Redis-cli usage (unauthorized direct Redis access)
#event_simpleName = "ProcessRollup2"
| FileName = /redis-cli/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, AuthenticationId])
```

#### tcpdump — Capture Redis data manipulation commands on application server

```text
tcpdump -i eth0 -w /captures/redis_data\_%Y%m%d.pcap -G 7200 -C 500 "tcp port 6379 and host <redis_server_ip>"
```

#### Datadog Log Search — File object access in Redis data directory

```text
source:windows @EventID:4663 @ObjectName:"\*Redis\*"
// time range: hunt window; requires File System SACL auditing configured on Redis data path
#### Datadog Log Search — Registry value modification on Redis configuration keys
source:windows @EventID:4657 message:"Redis"
// time range: hunt window; requires Object Access auditing on Redis registry keys
```
#### Windows Event IDs to collect

#### - Event ID 4663 (Object Access — File): monitor Redis data directory (C:\ProgramData\Redis\\ for unauthorized file reads or writes; requires SACL on the directory

Event ID 4657 (Registry Value Modified): monitor HKLM\SOFTWARE\Redis\\ and HKLM\SYSTEM\CurrentControlSet\Services\Redis\\ for unauthorized configuration changes

#### PowerShell — File access auditing on Redis data directory

```text
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4663;StartTime=(Get-Date).AddDays(-90)} |
Where-Object {$\_.Message -match 'Redis'} |
Select-Object TimeCreated,
@{N='ObjectName';E={$\_.Properties[6].Value}},
@{N='AccessMask';E={$\_.Properties[10].Value}},
@{N='ProcessName';E={$\_.Properties[11].Value}} |
Export-Csv -Path C:\hunt\redis_file_access.csv -NoTypeInformation
```

#### OT Data Collection: Claroty CTD — Administration \> Reports \> Process Anomalies, filter Device = Plant iT application server, date range = hunt window; export CSV and review for historian data deviation events or unexpected data write patterns to SCADA tag database

#### OT Data Collection: Dragos Platform — Investigate \> Threat Detection, filter Asset = Plant iT server; Behavioral alerts Category = Integrity Violation for deviations in expected process data patterns

#### OT Data Collection: Nozomi Networks — Assets \> Monitoring, review Process and Application layer alerts for data integrity deviations; GET /api/open/alerts?category=integrity

#### OT Data Collection: Armis — Asset Management \> Policy Violations, filter Device = application server; review for data-layer anomalies detected via behavioral baselines

#### OT Data Collection: Tenable OT — Reports \> Vulnerabilities, filter Asset = Plant iT server; Configuration Events view for unauthorized changes to historian data paths or Redis configuration

#### OT Data Collection: Forescout eyeInspect — Threat Detection panel, filter Device = application server; application-layer behavioral alerts for data manipulation patterns; GET /api/v1/alerts?device_ip=\<app_server_ip\>

#### YARA file-system scan — Redis data directory for unauthorized file drops

```text
yara -r redis_lua_rce.yar C:\ProgramData\Redis\data\\ >> C:\hunt\yara_redis_data_hits.txt
yara -r redis_lua_rce.yar C:\ProgramData\Redis\\ >> C:\hunt\yara_redis_data_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Redis-cli command-line arguments for data manipulation indicators
#event_simpleName = "ProcessRollup2"
| FileName = /redis-cli/i
| CommandLine = /^.\*(EVAL|FUNCTION|SET|DEL|HSET|FLUSHALL|CONFIG).\*/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, AuthenticationId])
```

#### Wireshark display filter — Redis SET or DEL write commands targeting process data keys

tcp.port == 6379 && (tcp.payload contains "SET" || tcp.payload contains "HSET" || tcp.payload contains "DEL")

#### tshark CLI — Extract Redis write commands from data capture for key-value inventory

```text
tshark -r /captures/redis_data_capture.pcap -Y 'tcp.port==6379 && tcp.flags.push==1' -T fields -e frame.time -e ip.src -e tcp.payload | grep -iE '(SET |HSET |DEL |FLUSHALL)' > C:\hunt\redis_write_cmds.txt
```

#### Datadog Log Analytics — File access frequency on Redis data directory by process name

```text
source:windows @EventID:4663 @ObjectName:"\*Redis\*"
// Analytics: Table view, group by @ProcessName, @ObjectName; time range: hunt window
#### Datadog Monitor — Redis registry configuration modification
Type: Log Alert
Query: source:windows @EventID:4657 message:"Redis"
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: Redis registry configuration modified on {{host.name}} — possible post-exploitation persistence or configuration tampering. @security-oncall"
Prerequisites: Windows Security Event Log (ID 4657) forwarded to Datadog; Object Access auditing and SACL configured on HKLM\SOFTWARE\Redis registry keys
```
Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### YARA memory scan — Redis process memory for Lua code injection execution artifacts

\$pid = (Get-Process redis-server | Select-Object -ExpandProperty Id -First 1)

```text
yara redis_lua_rce.yar $pid >> C:\hunt\yara_redis_mem_h3.txt
// CrowdStrike RTR: runscript -Raw=\`$p=(Get-Process redis-server -ErrorAction SilentlyContinue); if($p){yara redis_lua_rce.yar $p.Id}\` -HostIds=<agent_id>
```

## Hypothesis 4

An attacker has repeatedly triggered CVE-2025-46819 (out-of-bounds read / crash) against the Redis instance to cause service disruptions, observable as repeated Redis service crash events in Windows System Event Log and corresponding gaps in Plant iT process historian data continuity.

### MITRE ATT&CK

Impact | T1499.004 — Endpoint Denial of Service: Application or System Exploitation | Repeated exploitation of the CVE-2025-46819 out-of-bounds read crashes the Redis service, creating availability impact that disrupts Plant iT historian data continuity and may trigger process control failsafe modes or production halts.

### Collection Queries

#### CrowdStrike Falcon FQL — Redis process launch frequency (high restart count = crash loop)

```text
#event_simpleName = "ProcessRollup2"
| FileName = /redis-server/i
| groupBy([ComputerName, FileName], function=count(), limit=100000)
| sort(\_count, order=desc, limit=50)
#### CrowdStrike Falcon FQL — Services.exe launching Redis after crash recovery
#event_simpleName = "ProcessRollup2"
| FileName = /redis-server/i
| ParentBaseFileName = /services/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, AuthenticationId])
```

#### tcpdump — Capture traffic coinciding with Redis crash windows

```text
tcpdump -i eth0 -w /captures/redis_dos\_%Y%m%d\_%H%M.pcap -G 900 -C 200 "tcp port 6379 and host <redis_server_ip>"
```

#### Datadog Log Search — Redis service crash events (EventID 7034)

```text
source:windows @EventID:7034 message:"Redis"
// time range: hunt window; Analytics: Timeseries view, count by time; look for crash clustering
#### Datadog Log Search — Redis service state transitions (started/stopped cycles)
source:windows @EventID:7036 message:"Redis"
// time range: hunt window; correlate started/stopped timestamps to identify crash-restart cycles
```
#### Windows Event IDs to collect

Event ID 7034 (Service Crashed Unexpectedly): System log, filter for Redis service; repeated occurrences within a short window indicate active DoS exploitation

Event ID 7036 (Service State Change): System log, filter for Redis service transitioning between running and stopped states; correlate timestamps with packet capture to identify triggering source IP

Event ID 7045 (New Service Installed): System log, flag any new services installed coinciding with Redis crash windows as possible persistence mechanism established during crash-recovery window

#### PowerShell — Redis service crash event collection across full hunt window

```text
Get-WinEvent -FilterHashtable @{LogName='System';Id=@(7034,7036);StartTime=(Get-Date).AddDays(-90)} |
Where-Object {$\_.Message -match 'Redis'} |
Select-Object TimeCreated, Id, Message |
```

Sort-Object TimeCreated |

```text
Export-Csv -Path C:\hunt\redis_service_events.csv -NoTypeInformation
```

#### OT Data Collection: Claroty CTD — Administration \> Reports \> Availability Events, filter Device = Plant iT application server, date range = hunt window; review for connectivity loss events coinciding with Redis crash timestamps

#### OT Data Collection: Dragos Platform — Investigate \> Asset Timeline, filter Asset = Plant iT server; Availability events for downtime periods matching Redis crash windows from EventID 7034 log

#### OT Data Collection: Nozomi Networks — Assets \> Availability, filter IP = application server; export availability events via GET /api/open/availability?ip=\<app_server_ip\>; correlate offline periods with crash log timestamps

#### OT Data Collection: Armis — Asset Management \> Devices \> filter application server; Availability timeline for offline periods; REST API: GET /api/v1/devices/\<id\>/availability

#### OT Data Collection: Tenable OT — Assets \> Events, filter Asset = application server, Event Type = availability; correlate downtime windows with Redis System Event Log

#### OT Data Collection: Forescout eyeInspect — Inventory \> Devices \> filter application server; communication gap periods in device communication history panel; GET /api/v1/availability?ip=\<app_server_ip\>

#### YARA file-system scan — Windows Minidump directory for Redis crash dump artifacts

```text
yara -r redis_lua_rce.yar C:\Windows\Minidump\\ >> C:\hunt\yara_crash_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Daily Redis restart frequency (baseline deviation = crash exploitation)
#event_simpleName = "ProcessRollup2"
| FileName = /redis-server/i
| groupBy([ComputerName, #date(ContextTimeStamp)], function=count(), limit=100000)
| sort(\_count, order=desc, limit=90)
```

#### Wireshark display filter — High-rate SYN connections to Redis port (DoS volume indicator)

tcp.port == 6379 && tcp.flags.syn == 1 && !tcp.flags.ack == 1

#### tshark CLI — Count Redis SYN attempts per source IP for DoS source identification

```text
tshark -r /captures/redis_dos_capture.pcap -Y 'tcp.port==6379 && tcp.flags.syn==1 && !tcp.flags.ack' -T fields -e ip.src | sort | uniq -c | sort -rn > C:\hunt\redis_dos_sources.txt
```

#### Datadog Log Analytics — Redis crash event frequency over hunt window

```text
source:windows @EventID:7034 message:"Redis"
// Analytics: Timeseries view, count by @EventID; time range: hunt window
// A spike in crash count (>2 per 15 minutes) indicates active DoS exploitation or crash loop
#### Datadog Monitor — Redis repeated service crash alert
Type: Log Alert
Query: source:windows @EventID:7034 message:"Redis"
Evaluation window: last 15 minutes
Alert condition: count >= 2
Message: "ALERT: Redis service has crashed {{value}} times in 15 minutes on {{host.name}} — possible CVE-2025-46819 DoS exploitation or memory corruption instability. @security-oncall @plant-operations"
Prerequisites: Windows System Event Log forwarded to Datadog from all Plant iT application servers; alert threshold of 2 suppresses single spurious crash while detecting active exploitation patterns
```
Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### YARA memory scan — Redis process memory immediately after service restart (before GC clears artifacts)

\$pid = (Get-Process redis-server | Select-Object -ExpandProperty Id -First 1)

```text
yara redis_lua_rce.yar $pid >> C:\hunt\yara_redis_post_crash.txt
// Automate via Windows Service Recovery action to run scan on first failure restart event
```

# Threat Actor Profile

#### The CVE-2025-49844 (RediShell) vulnerability and its companion CVEs affect a widely deployed open-source data store with more than 300,000 instances estimated to be exposed on the internet globally. The threat landscape encompasses multiple adversary categories. Opportunistic criminal actors — ransomware affiliates, cryptominer operators, and initial access brokers — represent the most likely near-term threat given the public availability of proof-of-concept exploit code. These actors typically operate automated scanning pipelines to identify unpatched Redis instances and deploy post-exploitation tooling within minutes of obtaining a foothold. For Plant iT/Brewmaxx environments, an attacker who compromises the Redis service gains a Windows application server foothold with potential adjacency to OT network segments, making this an attractive target for ransomware actors who conduct IT/OT cross-environment attacks against manufacturing organizations.

#### Nation-state and advanced persistent threat actors with demonstrated interest in industrial and critical infrastructure represent a higher-sophistication concern. OT-targeting adversaries attributed to Russia, China, Iran, and North Korea by U.S. government reporting have shown sustained interest in gaining persistence on engineering and SCADA-adjacent servers that bridge IT and OT network tiers. Plant iT/Brewmaxx deployments in food and beverage manufacturing may be classified as critical infrastructure under applicable national frameworks. A persistent presence on the Plant iT application server provides access to real-time process telemetry, batch recipe histories, and a network vantage point with direct adjacency to PLC communication channels — intelligence and sabotage value well within the operating scope of state-sponsored ICS adversaries.

Insider threat actors with authorized Redis credentials represent a risk vector specific to CVE-2025-46818 (code injection across user context). A user with a low-privilege Redis account could leverage this flaw to elevate execution context to a more privileged Redis user without triggering standard authentication-based detection. Organizations with multiple Redis user accounts defined in their Plant iT/Brewmaxx deployment should audit user-level ACLs and review EVAL permission grants as part of their post-patch hardening review.

# Data Sources Required

The following data sources are required to execute this hunt plan in full.

***Network:*** Full packet capture (PCAP) from the Plant iT application server network interface during the hunt window; NetFlow or equivalent flow records from the firewall or switch port serving the application server; firewall allow/deny logs for TCP port 6379 ingress and all egress from the application server subnet.

***Endpoint:*** CrowdStrike Falcon sensor telemetry (ProcessRollup2, NetworkConnectIP4, NewExecutableWritten, RegGenericValueUpdate, DnsRequest, UserLogon) from all Plant iT application servers, VisuHub servers, and engineering workstations; Windows Security Event Log (IDs 4624, 4625, 4648, 4663, 4688, 4698, 4776) and System Event Log (IDs 7034, 7036, 7045) forwarded to Datadog or a central SIEM; Windows Registry and file system SACL-based auditing configured on Redis data directory (C:\ProgramData\Redis\\ and Redis registry keys (HKLM\SOFTWARE\Redis\\ HKLM\SYSTEM\CurrentControlSet\Services\Redis\\.

***OT/ICS:*** Historian data availability and gap reports from the Plant iT process historian covering the hunt window; SCADA alarm logs for unexpected setpoint deviations, historian write failures, or communication loss events; PLC and HMI connection logs or PCAP captures from the OT network segment showing connection attempts from the IT application tier; exports from all deployed OT monitoring platforms (Claroty CTD, Dragos, Nozomi, Armis, Tenable OT, Forescout eyeInspect) per Hypothesis 1 through 4 collection steps above.

***Vendor/Device Logs:*** Redis command log (enable with loglevel verbose and logfile /path/to/redis.log in redis.conf prior to hunting); Plant iT application and service event logs; ProLeiT patch deployment verification records confirming ProLeiT-2025-001 application status and Redis version across all in-scope assets.

# Detection Signatures

```text
title: Redis Server Spawning Suspicious Child Process
id: 7a3c9e2b-4d18-4a7f-b6e1-52c8a1f03d9e
status: experimental
description: Detects redis-server.exe spawning processes commonly associated with post-exploitation activity (cmd.exe, PowerShell, scripting hosts), indicating possible successful exploitation of CVE-2025-49844 (RediShell use-after-free) or CVE-2025-46817 (integer overflow) via a crafted Lua EVAL payload.
references:
- https://nvd.nist.gov/vuln/detail/CVE-2025-49844
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-083-03
author: 1898 & Co.
date: 2026-03-27
tags:
- attack.execution
- attack.t1190
- cve.2025.49844
logsource:
category: process_creation
product: windows
detection:
selection:
ParentImage|endswith: '\redis-server.exe'
Image|endswith:
- '\cmd.exe'
- '\powershell.exe'
- '\wscript.exe'
- '\cscript.exe'
- '\mshta.exe'
- '\certutil.exe'
- '\bitsadmin.exe'
- '\rundll32.exe'
- '\regsvr32.exe'
- '\wmic.exe'
- '\net.exe'
- '\net1.exe'
condition: selection
falsepositives:
- Administrative Redis management scripts that invoke cmd.exe or PowerShell for maintenance tasks
- Automated backup scripts configured under the Redis service account
level: high
title: Redis Server Initiating Outbound Non-Standard Network Connection
id: 1f8b4c7a-2e93-4b5d-9c2f-86d7e4a15c3b
status: experimental
description: Detects redis-server.exe establishing outbound network connections to ports other than TCP 6379 or to external IP addresses, which may indicate C2 beacon or lateral movement activity following exploitation of Redis Lua engine vulnerabilities (CVE-2025-49844, CVE-2025-46817, CVE-2025-46818).
references:
- https://nvd.nist.gov/vuln/detail/CVE-2025-49844
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-083-03
author: 1898 & Co.
date: 2026-03-27
tags:
- attack.command_and_control
- attack.t1071
- cve.2025.49844
logsource:
category: network_connection
product: windows
detection:
selection:
Image|endswith: '\redis-server.exe'
Initiated: 'true'
filter_redis_port:
DestinationPort: 6379
filter_localhost:
DestinationIp:
- '127.0.0.1'
- '::1'
condition: selection and not filter_redis_port and not filter_localhost
falsepositives:
- Redis cluster replication or Sentinel health-check connections on non-standard ports in custom cluster configurations
- Redis backup agents configured to push RDB files to remote storage on custom ports
level: high
title: Redis Service Repeated Crash Indicating Potential Denial of Service Exploitation
id: 3d2e7f9c-5a14-4e8b-c7d3-91a5b2f04e7c
status: experimental
description: Detects repeated Redis service crash events (EventID 7034) within a short time window, consistent with active exploitation of CVE-2025-46819 (out-of-bounds read causing denial of service) or memory corruption instability from CVE-2025-49844 exploitation attempts.
references:
- https://nvd.nist.gov/vuln/detail/CVE-2025-46819
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-083-03
author: 1898 & Co.
date: 2026-03-27
tags:
- attack.impact
- attack.t1499.004
- cve.2025.46819
logsource:
product: windows
service: system
detection:
selection:
EventID: 7034
Message|contains: 'Redis'
timeframe: 15m
condition: selection | count() > 2
falsepositives:
- Redis service crashes during patch application or planned maintenance windows
- Redis crashes due to legitimate memory pressure on under-provisioned application servers
level: medium
alert tcp any any -> any 6379 (
msg:"REDIS Lua EVAL Command - Potential CVE-2025-49844 RediShell Exploitation Attempt";
flow:established,to_server;
content:"EVAL"; nocase; depth:16;
content:"loadstring"; nocase; within:4096;
threshold:type both,track by_src,count 5,seconds 60;
classtype:attempted-admin;
sid:9002584; rev:1;
reference:cve,2025-49844;
metadata:affected_product Redis,created_at 2026_03_27,deployment Perimeter;
```
)

```text
alert tcp any any -> any 6379 (
msg:"REDIS FUNCTION LOAD Command - Potential CVE-2025-46818 Code Injection Attempt";
flow:established,to_server;
content:"FUNCTION"; nocase; depth:16;
content:"LOAD"; nocase; within:32;
threshold:type both,track by_src,count 3,seconds 60;
classtype:attempted-admin;
sid:9002585; rev:1;
reference:cve,2025-46818;
metadata:affected_product Redis,created_at 2026_03_27,deployment Perimeter;
)
```
**YARA Explanation:**

This rule targets file-system and disk artifacts associated with CVE-2025-49844 (RediShell) and CVE-2025-46817 exploitation. The string set covers: known exploit tool identifiers (RediShell, redis_exploit, CVE-2025-49844) used in public PoC tooling; Lua garbage collector manipulation patterns (collectgarbage, debug.getupvalue, debug.setupvalue) that are unique to the exploit payload class; and Lua shell execution calls (os.execute, io.popen) that indicate a second-stage RCE payload. The condition requires either a direct exploit identifier match (any \$rce\_\*) or a combination of two Lua manipulation strings plus a shell call, reducing false positives from legitimate scripts that may use individual GC calls in isolation. Scan the Redis program directory, data directory, and Windows Temp paths.

```text
rule Redis_Lua_RCE_Artifacts {
```

meta:

description = "Detects file artifacts associated with CVE-2025-49844 RediShell Redis Lua use-after-free RCE and CVE-2025-46817 integer overflow exploitation"

author = "1898 & Co."

date = "2026-03-27"

reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49844"

strings:

\$rce_1 = "RediShell" ascii nocase

\$rce_2 = "redis_exploit" ascii nocase

\$rce_3 = "CVE-2025-49844" ascii

\$lua_gc_1 = "collectgarbage" ascii

\$lua_gc_2 = "debug.getupvalue" ascii

\$lua_gc_3 = "debug.setupvalue" ascii

\$lua_eval = { 45 56 41 4C 20 22 }

\$shell_1 = "os.execute" ascii

\$shell_2 = "io.popen" ascii

\$shell_3 = "dofile" ascii

condition:

any of (\$rce\_\*) or ((2 of (\$lua_gc\_\*)) and (any of (\$shell\_\*)))

}

**YARA Explanation:**

***This rule targets the Redis server process memory for in-memory indicators of active Lua engine exploitation during or after a CVE-2025-49844 or CVE-2025-46817 attack. The rule matches on the co-presence of Redis command context strings (EVAL, in-memory as ASCII), Lua GC manipulation payloads (collectgarbage, debug.getupvalue), and shell execution artifacts (os.execute, io.popen, dofile). The three-component condition — two \$mem\_\* strings combined with any \$shell\_\* string — is designed to trigger only when both the exploit delivery mechanism and the shell execution payload are simultaneously resident in process memory, minimizing false positives from normal Redis Lua interpreter state. Execute against the live redis-server.exe PID immediately after detecting suspicious EVAL activity or after a service crash-restart cycle.***

```text
rule Redis_Lua_Memory_Exploitation {
```

meta:

description = "Detects in-memory indicators of active Redis Lua engine exploitation (CVE-2025-49844/CVE-2025-46817) in Redis server process memory"

author = "1898 & Co."

date = "2026-03-27"

reference = "https://nvd.nist.gov/vuln/detail/CVE-2025-49844"

strings:

\$mem_1 = "EVAL" ascii

\$mem_2 = "collectgarbage" ascii

\$mem_3 = "debug.getupvalue" ascii

\$mem_4 = { 6C 6F 61 64 73 74 72 69 6E 67 }

\$mem_5 = "pcall" ascii

\$shell_1 = "os.execute" ascii

\$shell_2 = "io.popen" ascii

\$shell_3 = "dofile" ascii

condition:

(2 of (\$mem\_\*)) and (any of (\$shell\_\*))

}

**YARA Explanation:**

#### This standing rule covers four known Windows credential dumping tool families: mimikatz (by name, hex-encoded string, and command signatures including sekurlsa::logonpasswords, lsadump::sam, and privilege::debug); Windows Credential Editor (WCE, matched on binary name plus lsass.exe co-presence); gsecdump (matched on name alone); and comsvcs-based MiniDump (matched on MiniDump plus comsvcs plus lsass.exe). A fifth catch-all branch matches any process containing native memory-read API strings (NtReadVirtualMemory or ReadProcessMemory) together with lsass.exe and at least one known tool indicator. This broad coverage ensures that renamed or repacked tools are detected if they retain LSASS-targeting artifacts. Note: this rule targets Windows LSASS-based credential dumping only and will not match Linux T1003.007 (/proc/mem) techniques — scope execution to Windows hosts exclusively; do not execute against Linux runner pools.

```text
rule Credential_Dump_Tool_Memory_Artifacts {
```

meta:

description = "Detects Windows credential dumping tool artifacts (mimikatz, WCE, gsecdump, comsvcs MiniDump) in process memory; Windows hosts only"

author = "1898 & Co."

date = "2026-03-27"

reference = "https://attack.mitre.org/techniques/T1003/"

strings:

\$mimi_1 = "sekurlsa::logonpasswords" ascii nocase

\$mimi_2 = "lsadump::sam" ascii nocase

\$mimi_3 = "privilege::debug" ascii nocase

\$mimi_4 = "mimikatz" ascii nocase

\$mimi_hex = { 6D 69 6D 69 6B 61 74 7A }

\$wce_tool = "wce.exe" ascii nocase

\$lsass = "lsass.exe" ascii nocase

\$gsec = "gsecdump" ascii nocase

\$comsvcs_1 = "MiniDump" ascii nocase

\$comsvcs_2 = "comsvcs" ascii nocase

\$api_1 = "NtReadVirtualMemory" ascii

\$api_2 = "ReadProcessMemory" ascii

condition:

(any of (\$mimi_1, \$mimi_2, \$mimi_3, \$mimi_4, \$mimi_hex)) or

(\$wce_tool and \$lsass) or

(\$gsec) or

(\$comsvcs_1 and \$comsvcs_2 and \$lsass) or

((any of (\$api\_\*)) and \$lsass and (any of (\$mimi_4, \$mimi_hex, \$wce_tool, \$gsec)))

}

# Indicators of Compromise

**Network IOCs**

No specific C2 IP addresses, domains, or network infrastructure indicators have been published in relation to CVE-2025-49844 exploitation activity targeting Schneider Electric Plant iT/Brewmaxx at the time of this advisory. Analysts should monitor for inbound TCP connections to port 6379 from external or unexpected internal IP ranges, outbound connections from redis-server.exe to external IP addresses or non-standard ports, and large repeated TCP flows on port 6379 consistent with bulk data exfiltration.

Host IOCs

#### Exploit tool: redis_exploit (CVE-2025-49844 public PoC) — publicly available; detect by YARA rule Redis_Lua_RCE_Artifacts or file hash if a staging copy is recovered during investigation.

**Behavioral IOCs**

redis-server.exe spawning cmd.exe, powershell.exe, wscript.exe, cscript.exe, or any scripting or LOLBin host

redis-server.exe initiating outbound TCP connections to ports other than 6379 or to external IP addresses

Redis service (EventID 7034) crashing two or more times within 15 minutes outside a documented maintenance window

EVAL or FUNCTION LOAD commands containing collectgarbage(), debug.getupvalue(), os.execute(), or io.popen() in Redis command logs

New files written to C:\ProgramData\Redis\\ or C:\Windows\Temp\\ by the Redis service account outside of normal backup schedules

Unauthorized modifications to HKLM\SOFTWARE\Redis\\ or HKLM\SYSTEM\CurrentControlSet\Services\Redis\\ registry keys (EventID 4657) outside maintenance windows

Network logons (EventID 4624 LogonType 3 or 10) originating from Plant iT application servers to OT-segment PLCs, HMIs, or RTUs

OT/Operational IOCs

Gaps in Plant iT process historian data tables coinciding with Redis crash windows identified in EventID 7034 log

SCADA alarm suppression or historian write failures during the hunt window

Unexpected connections from Plant iT application servers to PLC or HMI IP ranges on Modbus (TCP 502), EtherNet/IP (TCP/UDP 44818), OPC-UA (TCP 4840), or PROFINET (UDP 34964)

**Intelligence Feed Note**

No specific network or file IOCs (IP addresses, domains, SHA256 hashes) were published by CISA, NIST, or Schneider Electric in connection with ICSA-26-083-03 at the time of this advisory. Monitor the CISA Known Exploited Vulnerabilities catalog at https://www.cisa.gov/known-exploited-vulnerabilities-catalog for CVE-2025-49844 addition, which would indicate confirmed in-the-wild exploitation requiring immediate escalation response.

# False Positive Baseline

The following known-good patterns must be baselined and suppressed before escalating hunt findings:

1. Redis Management CLI Scripts: Legitimate administrators may invoke redis-cli.exe (not redis-server.exe) from PowerShell or cmd.exe for maintenance, backup verification, or health checks. Any child process alert should confirm redis-server.exe (not redis-cli.exe) as parent before escalating; verify that CommandLine matches expected maintenance flags such as --rdb or --cluster info.

2. Redis Cluster Peer Replication: In Redis Cluster configurations, redis-server.exe establishes TCP connections to peer node IPs on port 6379 or on the cluster bus port (6379 + 10000 = 16379 by default). Baseline all known peer node IP addresses and exclude their outbound connection events from the network IOC analysis before escalating.

3. Scheduled Backup and Persistence Writes: ProLeiT and Plant iT application backup agents write RDB dump files (dump.rdb) and AOF logs (appendonly.aof) to the Redis data directory on a known schedule. Baseline expected file write times and file name patterns in EventID 4663 monitoring to suppress known-good file access alerts.

4. Plant iT Application Service Restarts: The Plant iT platform may restart the Redis service component during scheduled maintenance windows, application upgrades, or Windows Update reboots. Correlate EventID 7034 crash events against the Plant iT maintenance calendar and change management records before escalating service crash alerts.

5. Legitimate Lua Scripting in Plant iT: The Plant iT/Brewmaxx platform may use Redis EVAL for scheduled batch processing, historian aggregation, or application-internal scripting. Obtain the list of expected Lua scripts from the Plant iT application team and build a hash or content whitelist to suppress known-good EVAL payloads before escalating anomalous EVAL command alerts from Redis command logs.

6. Engineering Workstation Redis Diagnostic Access: Engineering workstations may connect to the Plant iT application server on port 6379 for diagnostic or configuration purposes using authorized credentials. Baseline authorized engineering workstation IP addresses and suppress their TCP/6379 connection events from lateral movement and network IOC analysis.

# Escalation Criteria

The following specific conditions require immediate escalation to the incident response team:

1. Any confirmed child process (cmd.exe, powershell.exe, wscript.exe, or any scripting or LOLBin host) spawned directly by redis-server.exe, after all administrative maintenance script baselines from Section 7 have been excluded.

2. Any outbound TCP connection from redis-server.exe to an external IP address or to internal IP ranges outside of documented Redis cluster peer addresses.

3. Any YARA hit on rule Redis_Lua_RCE_Artifacts against files in the Redis data directory, Windows Temp, or the Redis program directory.

4. Any YARA hit on rule Redis_Lua_Memory_Exploitation against the live redis-server.exe process memory, indicating active in-memory Lua exploitation.

5. Three or more Redis service crashes (EventID 7034) within any 15-minute window outside of a documented maintenance event, consistent with active CVE-2025-46819 exploitation or crash-restart exploitation cycle.

#### 6. Any YARA hit on rule Credential_Dump_Tool_Memory_Artifacts against any process running on Plant iT application servers, after confirming the process is not an authorized security testing tool; this rule applies to Windows hosts only — do not execute against Linux systems.

7. Any network connection from a Plant iT application server to OT-segment PLCs, HMIs, or RTUs on control protocol ports (Modbus TCP 502, EtherNet/IP TCP/UDP 44818, OPC-UA TCP 4840) originating from a process other than the expected Plant iT application executable.

8. Any unauthorized modification to Redis registry configuration keys (EventID 4657) or Redis data directory files (EventID 4663) outside a documented change management window.

9. Any detection by Claroty CTD, Dragos, Nozomi, Armis, Tenable OT, or Forescout eyeInspect of an anomalous connection or behavioral alert originating from the Plant iT application server tier to OT network assets during the hunt window.

# Hunt Completion Criteria and Reporting

This hunt is considered complete when all of the following conditions are satisfied: all Plant iT/Brewmaxx deployments have been confirmed as patched to ProLeiT-2025-001 or running Redis 8.2.2 or later with patch status documented by version check output; all CrowdStrike Falcon FQL queries in Section 2 have been executed over the full hunt window with results reviewed and dispositioned; packet capture analysis for TCP port 6379 has been completed with all anomalous EVAL payloads reviewed against the false positive baseline in Section 7; all three YARA rules have been executed against file-system paths and live process memory on all in-scope hosts with zero unresolved hits; Windows Event Log collection and review for EventIDs 4624, 4663, 4688, 7034, and 7036 has been completed for all application servers and engineering workstations; and all six OT monitoring platforms have been queried per Section 2 steps with results reviewed and no open escalation-worthy findings.

Per Section 8 Escalation Criteria items 3 and 4: any YARA hit on Redis_Lua_RCE_Artifacts (Criterion 3) or Redis_Lua_Memory_Exploitation (Criterion 4) against redis-server.exe or its working paths must be included as a numbered escalation condition in the hunt completion report and must not be closed without a confirmed benign disposition or full IR engagement.

The hunt completion report must include: an asset inventory table of all Plant iT/Brewmaxx servers with confirmed patch status and Redis version; a summary of all CrowdStrike Falcon query results with hit counts and analyst disposition; YARA scan results for all three rules with hit counts and notes; PCAP analysis summary with anomalous EVAL commands identified and reviewed; Windows Event Log anomaly summary; OT platform export review summary; a list of any open findings requiring further investigation; and confirmation of whether Section 5 detection signatures and Section 2 Datadog Monitors have been deployed to production detection infrastructure.

# Advisory IoC Reference

| IOC Type | IOC |
|----|----|
| CVE | CVE-2025-49844 | CVSS v3.1 9.9 Critical | Schneider Electric Plant iT/Brewmaxx 9.60+ (Redis ≤ 8.2.1) | Use-after-free in Redis Lua garbage collector enabling authenticated remote code execution; fixed in Redis 8.2.2 / ProLeiT-2025-001 |
| CVE | CVE-2025-46817 | CVSS v3.1 8.8 High | Schneider Electric Plant iT/Brewmaxx 9.60+ (Redis ≤ 8.2.1) | Integer overflow in Redis Lua scripting engine enabling authenticated remote code execution; fixed in Redis 8.2.2 |
| CVE | CVE-2025-46818 | CVSS v3.1 7.3 High | Schneider Electric Plant iT/Brewmaxx 9.60+ (Redis ≤ 8.2.1) | Code injection via Lua object manipulation enabling code execution in context of another Redis user; fixed in Redis 8.2.2 |
| CVE | CVE-2025-46819 | CVSS v3.1 7.1 High | Schneider Electric Plant iT/Brewmaxx 9.60+ (Redis ≤ 8.2.1) | Out-of-bounds read via crafted Lua script causing memory disclosure or server crash (DoS); fixed in Redis 8.2.2 |
| Threat Actor | None attributed | No specific threat actor attributed to ICSA-26-083-03; vulnerability exploitable by opportunistic criminal actors using public PoC (RediShell) |
| Malware | redis_exploit (RediShell PoC) | Public proof-of-concept exploit for CVE-2025-49844 published at github.com/raminfp/redis_exploit; no confirmed malware family deployment reported |
| Network IOC | None published in source material — monitor CISA KEV catalog for CVE-2025-49844 addition: https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| File IOC | None published in source material — use YARA rule Redis_Lua_RCE_Artifacts for staged exploit artifact detection |
| Behavioral | redis-server.exe spawning cmd.exe or powershell.exe child process | Post-exploitation shell execution following Lua RCE via EVAL |
| Behavioral | EVAL command containing collectgarbage() or debug.getupvalue() in Redis command log | CVE-2025-49844 RediShell Lua exploit payload delivery pattern |
| Behavioral | Redis service EventID 7034 crash occurring 2+ times within 15 minutes | CVE-2025-46819 DoS exploitation or memory corruption crash loop |
| Behavioral | redis-server.exe outbound TCP connection to non-port-6379 or external IP | Post-exploitation C2 beacon or data exfiltration following RCE |
| Behavioral | New file written to C:\ProgramData\Redis\\ by Redis service account outside backup schedule | Potential backdoor staging or payload drop following code execution |
