# Threat Hunt Plan: TeamPCP / Trivy Supply Chain Compromise — Malicious v0.69.4 Release and GitHub Actions Hijack

Revision 1.0 | 20 March 2026

1. Hunt Objective and Scope

This hunt seeks to determine whether any systems or CI/CD pipelines within the in-scope environment executed the malicious Trivy v0.69.4 binary or ran GitHub Actions workflows referencing the compromised aquasecurity/trivy-action or aquasecurity/setup-trivy repositories during the exposure window of 17:43 UTC to 23:13 UTC on March 19, 2026. Secondary objectives are to identify any credential exfiltration to TeamPCP C2 infrastructure, detect post-exfiltration activity using stolen runner credentials, and uncover any tpcp-docs repository artifacts that indicate successful data staging. The hunt covers all environments where GitHub-hosted or self-hosted GitHub Actions runners are used, as well as any systems that pull and execute Trivy binaries from official distribution channels including GitHub Releases, Docker Hub, GHCR, and Amazon ECR.

Time window: primary focus on March 19, 2026 17:00 UTC through March 21, 2026 00:00 UTC. Expand to March 1, 2026 through present if any indicators are found, given the initial intrusion date of February 28, 2026.

In-scope data sources: GitHub Actions audit logs, CrowdStrike Falcon endpoint telemetry from CI/CD build hosts and container runtimes, Kubernetes and container orchestration logs, cloud provider activity logs (AWS CloudTrail, GCP Audit Logs, Azure Activity Log), container registry access logs (ECR, GHCR, Docker Hub), and outbound network logs from CI/CD runner infrastructure.

2. Hypotheses and Hunt Procedures

Hypothesis 1: TeamPCP has caused the malicious Trivy v0.69.4 binary to execute in CI/CD runner environments, observable as trivy spawning unexpected child processes (Python, curl, wget, sh) or executing from an unexpected hash in CrowdStrike process telemetry.

MITRE ATT&CK: Defense Evasion / Initial Access | T1195.002 — Compromise Software Supply Chain | The malicious Trivy binary was distributed through all official Aquasecurity channels, causing it to be executed as a trusted tool during scheduled security scanning steps; any resulting child process activity is a primary indicator of active compromise.

### Collection Queries

CrowdStrike Falcon — Trivy child process collection (any process spawned by trivy that is not expected scanner output):

```text
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = "trivy"
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, SHA256HashData, timestamp])
```

CrowdStrike Falcon — All trivy process executions with hash for comparison against known-good (v0.69.3 and earlier):

// Collect all trivy invocations to build a hash inventory; rarest hashes first indicate anomalies

```text
#event_simpleName = "ProcessRollup2"
| FileName = "trivy"
| groupBy([ComputerName, FileName, SHA256HashData, ImageFileName], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
```

CrowdStrike Falcon — Runner.Worker process spawning unexpected children (GitHub Actions self-hosted runners):

// Runner.Worker is the GitHub Actions runner host process; unexpected children indicate payload execution

```bash
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = "Runner.Worker"
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, SHA256HashData, ImageFileName, timestamp])
tcpdump — Capture all traffic to/from CI/CD runner host during a timed scan window:
```

sudo tcpdump -i eth0 -w /tmp/trivy_hunt\_%Y%m%d\_%H%M%S.pcap -G 300 -C 100 \\

'host 45.148.10.212 or port 443'

```text
YARA file-system scan for TeamPCP Cloud Stealer Python script on disk:
yara -r -p 4 /tmp/TeamPCP_Cloud_Stealer_Script.yar /home /tmp /var /opt >> /tmp/yara_hits_h1.txt 2>&1
```

Windows Event ID collection (Windows-hosted runners only) — Process creation for trivy:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-3)} |
Where-Object { $\_.Properties[5].Value -match 'trivy' -or $\_.Properties[9].Value -match 'trivy' } |
Select-Object TimeCreated,@{N='NewProcess';E={$\_.Properties[5].Value}},@{N='CmdLine';E={$\_.Properties[8].Value}},@{N='ParentProcess';E={$\_.Properties[13].Value}} |
Export-Csv /tmp/trivy_proc_events.csv -NoTypeInformation
```

Datadog Log Search — Container/Kubernetes logs for trivy execution and unexpected child activity:

// time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z

```bash
source:kubernetes message:"trivy" @kubernetes.namespace_name:\* status:error
// Follow-up: look for python3 or curl launched in the same container/pod immediately after trivy
source:kubernetes (message:"python3" OR message:"curl") @kubernetes.pod_name:\*
// Analytics: Table view, group by @kubernetes.pod_name, @kubernetes.container_name; time range above
```

Datadog Live Process Monitoring (Infrastructure \> Processes — NOT a log source):

```bash
command:trivy
// Review spawned children in the process tree; look for python3, curl, or wget as immediate children
command:python3 user:root
// Prerequisite: Datadog Agent with process_config.process_collection.enabled: true on runner hosts
```

### Analysis Queries

CrowdStrike Falcon — Frequency analysis: most common trivy parent processes (unexpected parents indicate compromised runners):

```text
#event_simpleName = "ProcessRollup2"
| FileName = "trivy"
| top([ComputerName, ParentBaseFileName, ImageFileName], limit=50)
```

CrowdStrike Falcon — Rarity analysis: least common trivy SHA256 hashes (rare hashes indicate malicious binary):

```text
#event_simpleName = "ProcessRollup2"
| FileName = "trivy"
| groupBy([SHA256HashData, ImageFileName], function=count(), limit=100000)
| sort(\_count, order=asc, limit=20)
```

CrowdStrike Falcon — Timeline: all process events on hosts that ran trivy during exposure window:

// time range: 2026-03-19T17:43:00Z to 2026-03-19T23:13:00Z

```text
#event_simpleName = "ProcessRollup2"
| join(
query={
#event_simpleName=ProcessRollup2
| FileName = "trivy"
| groupBy([aid, ComputerName], function=count(), limit=100000)
},
field=aid,
include=\[ComputerName\]
)
| table(\[ComputerName, FileName, CommandLine, ParentBaseFileName, SHA256HashData, timestamp\])
```

Wireshark display filter — Connections to TeamPCP C2 from runner PCAP:

ip.addr == 45.148.10.212 && tcp.port == 443

// tshark equivalent:

```bash
tshark -r /tmp/trivy_hunt\_\*.pcap -Y "ip.addr == 45.148.10.212 && tcp.port == 443" \\
-T fields -e frame.time -e ip.src -e ip.dst -e tcp.port -e http2.headers.method 2>/dev/null
```

Datadog Log Analytics — Trivy execution frequency by host and namespace:

// Log Search base: source:kubernetes message:"trivy"

// Analytics: Timeseries view, group by @kubernetes.namespace_name; time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z

// Equivalent to CQL: groupBy(\[namespace, pod\], function=count(), limit=100000)

Datadog Monitor — Alert on trivy spawning unexpected child process (H1):

```text
Type: Log Alert
Query: source:kubernetes (message:"python3" OR message:"curl" OR message:"wget") @kubernetes.pod_name:\*trivy\*
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: Possible malicious Trivy child process detected in pod @kubernetes.pod_name — immediate pipeline suspension required @security-oncall"
```

Prerequisites: Kubernetes container stdout/stderr logs must be forwarded to Datadog via the Datadog Agent log collection integration; source:kubernetes must be active

Windows Event Log analysis — Parent-child process chain from trivy (Windows runners):

\$trivyProcs = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-3)} |

```powershell
Where-Object { $\_.Properties[5].Value -match 'trivy' }
```

\$trivyProcs | ForEach-Object {

\$pid = $_.Properties\[6\].Value

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$\_.TimeCreated; EndTime=$\_.TimeCreated.AddSeconds(10)} |
Where-Object { $\_.Properties[13].Value -match [regex]::Escape($pid) } |
Select-Object TimeCreated,@{N='ChildProcess';E={$\_.Properties[5].Value}},@{N='CmdLine';E={$\_.Properties[8].Value}}
} | Export-Csv /tmp/trivy_children.csv -NoTypeInformation
YARA memory scan — Scan all running Python processes for TeamPCP Cloud Stealer indicators:
```

for pid in \$(ps aux | grep python3 | awk '{print \$2}'); do

sudo yara -p 2 /tmp/TeamPCP_Cloud_Stealer_Memory.yar \$pid 2\>/dev/null && echo "HIT: PID \$pid"

done \>\> /tmp/yara_memory_hits.txt

// Note: Requires root or ptrace_scope=0; CrowdStrike RTR alternative: run via Real Time Response custom script on affected hosts

Hypothesis 2: TeamPCP Cloud Stealer has read GitHub Actions Runner.Worker process memory via the Linux /proc filesystem to extract in-memory CI/CD secrets, observable as Python processes accessing /proc/\<pid\>/maps and /proc/\<pid\>/mem file paths in process or file telemetry.

MITRE ATT&CK: Credential Access | T1003.007 — OS Credential Dumping: Proc Filesystem | The credential stealer directly reads the Runner.Worker process heap by mapping /proc/\<pid\>/maps and then reading /proc/\<pid\>/mem at the identified offset ranges, bypassing GitHub Actions secret masking controls that only redact secrets in log output.

### Collection Queries

CrowdStrike Falcon — Python processes with /proc references in command line (Linux runners):

```text
#event_simpleName = "ProcessRollup2"
| FileName = "python3"
| CommandLine = /\\proc\\/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, SHA256HashData, timestamp])
```

CrowdStrike Falcon — Any process on runner hosts spawned by trivy or Runner.Worker within 60 seconds of trivy execution:

// Collect all process events from hosts that ran trivy in the exposure window

// Focus on python3, sh, bash, curl, wget spawned directly after trivy

```text
#event_simpleName = "ProcessRollup2"
| in(FileName, values=["python3","python","sh","bash","curl","wget"])
| ParentBaseFileName = "trivy"
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ImageFileName, SHA256HashData, timestamp])
```

CrowdStrike Falcon — CriticalFile events on /proc paths (if Linux file telemetry is enabled):

```bash
#event_simpleName = "CriticalFile"
| TargetFileName = /\\proc\[0-9]+\\mem/i
| table([ComputerName, TargetFileName, ContextProcessId, timestamp])
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId]), limit=100000)},
field=[aid,ContextProcessId], key=[aid,TargetProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId]
)
tcpdump — Monitor runner host for /proc access patterns correlated with Python process:
```

sudo tcpdump -i lo -w /tmp/runner_local\_%Y%m%d.pcap -G 300 -C 50 \\

'not port 22'

```text
YARA file-system scan for TeamPCP Python stealer script artifacts:
yara -r -p 4 /tmp/TeamPCP_Cloud_Stealer_Script.yar / --exclude-dirs /proc --exclude-dirs /sys >> /tmp/yara_hits_h2.txt 2>&1
```

Windows Event ID collection (Windows runners with Sysmon) — File access on sensitive paths:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=10; StartTime=(Get-Date).AddDays(-3)} |
Where-Object { $\_.Properties[5].Value -match 'Runner.Worker' -or $\_.Properties[9].Value -match 'Runner.Worker' } |
Select-Object TimeCreated,@{N='SourceProcess';E={$\_.Properties[5].Value}},@{N='TargetProcess';E={$\_.Properties[9].Value}} |
Export-Csv /tmp/runner_proc_access.csv -NoTypeInformation
// Sysmon Event ID 10 = ProcessAccess; detects PROCESS_VM_READ on Runner.Worker
```

Datadog Log Search — Container logs showing /proc access patterns:

// time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z

```text
source:kubernetes (message:"/proc/" OR message:"Runner.Worker" OR message:"isSecret")
// Analytics: Table view, group by @kubernetes.pod_name; time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z
```

Datadog Live Process Monitoring (Infrastructure \> Processes):

```text
command:python3 user:root
// Look for python3 processes with open file handles to /proc paths — review command line arguments
```

### Analysis Queries

CrowdStrike Falcon — Frequency analysis of Python processes launched by runner-related parents:

```text
#event_simpleName = "ProcessRollup2"
| FileName = "python3"
| groupBy([ComputerName, ParentBaseFileName, CommandLine], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
```

CrowdStrike Falcon — Timeline of events on hosts where python3 accessed /proc:

// Start with hosts identified from CriticalFile or ProcessRollup2 /proc findings, then pull all events

```text
#event_simpleName = "ProcessRollup2"
| ComputerName = "<identified_host>"
| ContextTimeStamp > "2026-03-19T17:00:00Z"
| ContextTimeStamp < "2026-03-20T00:00:00Z"
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, SHA256HashData, ContextTimeStamp])
```

Wireshark — Correlate /proc access timing with outbound connection bursts:

// Filter for any outbound connection within 5 seconds of a process creation event

frame.time_relative \>= 0 && ip.dst != 10.0.0.0/8 && tcp.flags.syn == 1

// tshark:

```bash
tshark -r /tmp/runner\_\*.pcap -Y "ip.dst != 10.0.0.0/8 and tcp.flags.syn == 1" \\
-T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | head -100
```

Datadog Log Analytics — Anomalous Python process activity correlated with trivy timing:

// Log Search base: source:kubernetes message:"python3"

// Analytics: Timeseries view, group by @kubernetes.pod_name; time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z

// Look for python3 log events that appear within the same pod immediately after trivy executions

Datadog Monitor — Alert on /proc filesystem access patterns in container logs (H2):

```text
Type: Log Alert
Query: source:kubernetes (message:"/proc/" AND message:"mem") @kubernetes.namespace_name:\*
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: Possible /proc/pid/mem access detected in Kubernetes pod @kubernetes.pod_name — potential in-memory secret extraction in progress @security-oncall"
```

Prerequisites: Kubernetes pod stdout/stderr logs must be collected by the Datadog Agent; application must write /proc access activity to stdout (may require verbose logging mode)

Datadog Audit Trail — Check for any secret management API calls from CI/CD service accounts:

// Access via Datadog Admin \> Audit Trail or GET /api/v2/audit/events?filter\[query\]=...

```text
source:datadog @evt.category:user_access @evt.name:secret_get
// Also check for anomalous API key usage from runner source IPs during the exposure window
YARA memory scan — All running Python processes for in-memory stealer indicators:
```

for pid in \$(pgrep python3); do

sudo yara -p 2 /tmp/TeamPCP_Cloud_Stealer_Memory.yar \$pid 2\>/dev/null && echo "MEMORY HIT: PID \$pid"

done \>\> /tmp/yara_memory_hits_h2.txt

// CrowdStrike RTR equivalent: use Real Time Response to run custom YARA scan against Python PIDs on affected hosts

```text
YARA memory scan — Scan Runner.Worker process for evidence of being read (residual heap artifacts):
```

sudo yara -p 2 /tmp/Credential_Dump_Tool_Memory_Artifacts.yar \$(pgrep Runner.Worker) 2\>/dev/null

// Note: Credential_Dump_Tool_Memory_Artifacts covers Windows LSASS credential tool patterns; for Linux runners

// this serves as a secondary check for any Windows-ported credential tool artifacts if mixed-OS runner pools are in scope

Hypothesis 3: TeamPCP Cloud Stealer has exfiltrated encrypted credential archives to C2 infrastructure at 45.148.10.212 (scan.aquasecurtiy\[.\]org), observable as outbound HTTPS POST connections carrying the custom header X-Filename: tpcp.tar.gz in network telemetry from CI/CD runner hosts.

MITRE ATT&CK: Exfiltration | T1041 — Exfiltration Over C2 Channel | The stealer transmits a hybrid-encrypted (AES-256-CBC + RSA-4096 OAEP) credential archive to the primary C2 endpoint via HTTPS POST with the distinctive X-Filename: tpcp.tar.gz header; detection is possible via IP/domain reputation, DNS telemetry, and network flow analysis.

### Collection Queries

CrowdStrike Falcon — Outbound connections to TeamPCP C2 IP with process context:

```text
#event_simpleName = "NetworkConnectIP4"
| RemoteAddressIP4 = "45.148.10.212"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]
)
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName, timestamp])
```

CrowdStrike Falcon — DNS queries for typosquatted aquasecurtiy domain:

```text
#event_simpleName = "DnsRequest"
| DomainName = /aquasecurtiy/i
| table([ComputerName, DomainName, IpAddress, RequestType, timestamp])
```

CrowdStrike Falcon — Outbound HTTPS connections to any non-RFC-1918 address from python3:

// Capture all external connections initiated by Python processes — broaden scope if C2 rotates

```bash
#event_simpleName = "NetworkConnectIP4"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]
)
| FileName = "python3"
| not cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8"])
| table([ComputerName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName, timestamp])
tcpdump — Targeted capture on TeamPCP C2 IP and typosquatted domain on runner host:
```

sudo tcpdump -i eth0 -w /tmp/c2_hunt\_%Y%m%d\_%H%M%S.pcap -G 300 -C 100 \\

'(host 45.148.10.212 or host plug-tab-protective-relay.trycloudflare.com) and tcp port 443'

Windows Event ID collection (Windows runners) — Network connections from python:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-3)} |
Where-Object { $\_.Properties[1].Value -match 'python' } |
Select-Object TimeCreated,@{N='Application';E={$\_.Properties[1].Value}},@{N='DestAddr';E={$\_.Properties[5].Value}},@{N='DestPort';E={$\_.Properties[6].Value}} |
Where-Object { $\_.DestAddr -notmatch '^(10|172\\(1[6-9]|2[0-9]|3[01])|192\\168\\)' } |
Export-Csv /tmp/python_network_events.csv -NoTypeInformation
```

Datadog Log Search — Container network activity to TeamPCP C2:

// time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z

```text
source:kubernetes @network.destination.ip:45.148.10.212
// Alternative if network logs are not in Datadog:
source:cloudtrail @evt.name:CreateNetworkAclEntry
// Data source gap note: VPC flow logs must be enabled and forwarded to Datadog for L3 visibility;
// if unavailable, fall back to Datadog NPM (Network Performance Monitoring) if deployed on runner hosts
```

Datadog Live Process Monitoring (Infrastructure \> Processes):

```text
command:python3 user:root
// Correlate python3 processes on runner hosts at timestamps matching the exposure window
```

### Analysis Queries

CrowdStrike Falcon — Frequency analysis: all external destinations contacted by Python processes on runner hosts:

```text
#event_simpleName = "NetworkConnectIP4"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([FileName,CommandLine,ParentBaseFileName]), limit=100000)},
field=[aid,RawProcessId],
include=[FileName,CommandLine,ParentBaseFileName]
)
| FileName = "python3"
| not cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"])
| groupBy([RemoteAddressIP4, RemotePort, ComputerName], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
```

CrowdStrike Falcon — DNS rarity analysis for unusual domains queried by runner hosts:

```text
#event_simpleName = "DnsRequest"
| groupBy([DomainName, ComputerName], function=count(), limit=100000)
| sort(\_count, order=asc, limit=100)
// Look for single-occurrence domain queries — high suspicion for C2 beacons
```

Wireshark — Identify POST requests and custom headers in TLS session (requires decryption key or plaintext capture):

http.request.method == "POST" && http.host contains "aquasecurtiy"

// If TLS: look for TLS ClientHello SNI field matching aquasecurtiy

tls.handshake.extensions_server_name contains "aquasecurtiy"

// tshark:

```bash
tshark -r /tmp/c2_hunt\_\*.pcap \\
```

-Y "tls.handshake.extensions_server_name contains \\aquasecurtiy\\" \\

-T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name 2\>/dev/null

Datadog Log Analytics — Outbound connection volume by destination IP from Kubernetes pods:

// Log Search base: source:kubernetes @network.destination.ip:\*

// Analytics: Top List view, group by @network.destination.ip; time range: 2026-03-19T17:00Z to 2026-03-20T00:00Z

// Flag any destination IPs that appear in only one or two pod logs — C2 connections are typically low-frequency

Datadog CloudTrail — Check for unauthorized cloud API calls using exfiltrated runner credentials:

// time range: 2026-03-19T17:00Z to 2026-03-21T00:00Z

```text
source:cloudtrail @evt.name:(AssumeRole OR GetSecretValue OR CreateUser OR AttachUserPolicy OR PutBucketPolicy) -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// Analytics: Table view, group by @userIdentity.arn, @network.client.ip; time range above
// Look for calls from unexpected source IPs using CI/CD service account ARNs
```

Datadog Monitor — Alert on outbound connection to TeamPCP C2 IP in network logs (H3):

```text
Type: Log Alert
```

Query: @network.destination.ip:45.148.10.212

```text
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: Outbound connection to TeamPCP C2 IP 45.148.10.212 detected from @host — immediate network isolation of runner host required @security-oncall"
```

Prerequisites: Network Performance Monitoring (NPM) or VPC flow logs must be forwarded to Datadog; @network.destination.ip attribute requires NPM agent or flow log parser

Datadog Audit Trail — Review API key usage from CI/CD runner source IPs:

```text
source:datadog @evt.category:api_key_management @evt.name:api_key_created
// Also check: source:datadog @evt.category:integration_management to detect new webhook or integration creation from runner IPs
```

Windows Event Log — DNS resolution events for typosquatted domain (Windows runners):

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; Id=3008; StartTime=(Get-Date).AddDays(-3)} |
Where-Object { $\_.Message -match 'aquasecurtiy' } |
Select-Object TimeCreated,@{N='DomainName';E={$\_.Properties[0].Value}} |
Export-Csv /tmp/dns_aquasecurtiy.csv -NoTypeInformation
```

Hypothesis 4: TeamPCP has staged exfiltrated credential archives by creating attacker-controlled public repositories named tpcp-docs on victim GitHub accounts using stolen runner GITHUB_TOKEN credentials, observable as unexpected repository creation events in GitHub audit logs or CloudTrail API telemetry.

MITRE ATT&CK: Exfiltration | T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository | When the primary C2 (45.148.10.212) is unreachable, the stealer authenticates to GitHub API using the runner's GITHUB_TOKEN and creates a public repository named tpcp-docs to upload the encrypted credential archive, using the victim organization's own GitHub identity as a staging host.

### Collection Queries

CrowdStrike Falcon — HTTPS connections to api.github.com from Python processes (fallback C2 path):

```bash
#event_simpleName = "DnsRequest"
| DomainName = "api.github.com"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)},
field=[aid,ContextProcessId], key=[aid,TargetProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]
)
| FileName = "python3"
| table([ComputerName, DomainName, FileName, CommandLine, ParentBaseFileName, timestamp])
tcpdump — Capture GitHub API traffic from runner host during exposure window:
```

sudo tcpdump -i eth0 -w /tmp/github_api\_%Y%m%d\_%H%M%S.pcap -G 300 -C 50 \\

'host api.github.com and tcp port 443'

Windows Event ID collection (Windows runners) — GitHub API connections from python processes:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-3)} |
Where-Object { $\_.Properties[5].Value -eq '140.82.114.5' -or $\_.Properties[5].Value -match '192\\30\\' } |
Select-Object TimeCreated,@{N='App';E={$\_.Properties[1].Value}},@{N='DestIP';E={$\_.Properties[5].Value}} |
Export-Csv /tmp/github_api_events.csv -NoTypeInformation
```

Datadog Log Search — GitHub audit log for tpcp-docs repository creation events:

// time range: 2026-03-19T17:00Z to 2026-03-21T00:00Z

```text
source:github.audit @action:repo.create
// Filter further:
source:github.audit @action:repo.create @data.repository:\*tpcp\*
```

Datadog CloudTrail — GitHub API Create Repository events via AWS CodeBuild or similar integrations:

// time range: 2026-03-19T17:00Z to 2026-03-21T00:00Z

```text
source:cloudtrail @evt.name:CreateRepository @requestParameters.repositoryName:\*tpcp\*
// Also check for unexpected repository visibility changes (private to public):
source:cloudtrail @evt.name:UpdateRepository
```

Datadog Live Process Monitoring (Infrastructure \> Processes):

```text
command:python3 user:runner
// Look for python3 processes on runner hosts at times matching the exposure window; review full command lines
```

### Analysis Queries

CrowdStrike Falcon — GitHub API DNS query frequency analysis (runner hosts making unexpected queries to api.github.com):

```text
#event_simpleName = "DnsRequest"
| DomainName = "api.github.com"
| groupBy([ComputerName, DomainName], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
```

Wireshark — TLS SNI analysis for GitHub API connections from runner PCAP:

tls.handshake.extensions_server_name == "api.github.com"

// tshark:

```bash
tshark -r /tmp/github_api\_\*.pcap \\
```

-Y "tls.handshake.extensions_server_name == \\api.github.com\\" \\

-T fields -e frame.time -e ip.src -e ip.dst 2\>/dev/null

Datadog Log Analytics — GitHub audit log repository creation events by actor:

// Log Search base: source:github.audit @action:repo.create

// Analytics: Table view, group by @actor, @data.repository; time range: 2026-03-19T17:00Z to 2026-03-21T00:00Z

// Flag any repository created by a runner service account or bot that does not match known automation

Datadog CloudTrail — Identify exfiltration patterns: unexpected file uploads to new repositories:

// time range: 2026-03-19T17:00Z to 2026-03-21T00:00Z

```text
source:cloudtrail @evt.name:PutObject @requestParameters.bucketName:\*tpcp\* -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// Analytics: Table view, group by @userIdentity.arn, @requestParameters.bucketName; time range above
```

Datadog Monitor — Alert on tpcp-docs repository creation in GitHub audit log (H4):

```text
Type: Log Alert
Query: source:github.audit @action:repo.create @data.repository:\*tpcp\*
Evaluation window: last 15 minutes
Alert condition: count > 0
Message: "ALERT: Repository matching 'tpcp-docs' pattern created in GitHub org by actor @actor — possible TeamPCP credential staging; revoke associated token and review audit log immediately @security-oncall"
```

Prerequisites: GitHub audit log streaming must be configured to forward events to Datadog via GitHub Audit Log Streaming (Organization Settings \> Audit Log \> Log Streaming); source:github.audit must be active

Datadog Audit Trail — Review for token creation or OAuth app authorization from runner IP ranges:

```text
source:datadog @evt.category:api_key_management
// Check for any new API key or OAuth app created from IP ranges associated with runner infrastructure during or after the exposure window
```

3. Threat Actor Profile

TeamPCP is an advanced supply chain threat actor with demonstrated capability to compromise major open-source security tooling repositories through GitHub organization takeover techniques. The actor was responsible for a prior compromise of Trivy in February 2026 and retained access through the incomplete revocation of the aqua-bot service account PAT, demonstrating operational patience and persistence across incident response cycles. The use of a typosquatted C2 domain (scan.aquasecurtiy\[.\]org), hybrid RSA-AES encryption, and a coordinated spam bot flooding campaign on March 20, 2026 (17 accounts) indicates an organized, well-resourced actor with multiple simultaneous capabilities. The alias "teampcp" and bot identifier "hackerbot-claw" have been attributed to both compromises. The fallback C2 mechanism — creating tpcp-docs repositories using victim GitHub credentials — demonstrates sophistication in operational security through co-optation of victim infrastructure.

TeamPCP's primary objective in this campaign was credential harvesting from CI/CD pipelines, targeting secrets that enable lateral movement into production cloud environments, container registries, and source code repositories. The actor's targeting of GitHub Actions and widely-deployed open-source security tooling is consistent with a strategy of maximizing blast radius through a single high-trust supply chain insertion point. The coordinated spam bot activity following the compromise suggests the actor may be attempting to obscure forensic investigation timelines or distract security operations teams during the exfiltration window.

Primary TTPs observed in this campaign: T1195.002 (Compromise Software Supply Chain), T1003.007 (OS Credential Dumping: Proc Filesystem), T1041 (Exfiltration Over C2 Channel), T1567.001 (Exfiltration to Code Repository), T1078.004 (Valid Accounts: Cloud Accounts — using exfiltrated tokens for post-exfiltration pivoting).

4. Data Sources Required

Endpoint Telemetry: CrowdStrike Falcon sensor deployed on all CI/CD runner hosts (Linux and Windows), with process creation, DNS request, network connection, and critical file telemetry enabled. Linux process telemetry must be active to capture /proc filesystem access via CriticalFile events. GitHub Actions self-hosted runner hosts must have the Falcon sensor installed and reporting.

Container and Orchestration Logs: Kubernetes pod stdout/stderr log collection via the Datadog Agent log collection integration (or equivalent SIEM forwarder). Container runtime logs for any Docker-in-Docker or container-based runner deployments. GitHub Actions hosted runner logs via GitHub Actions API (GET /repos/{owner}/{repo}/actions/runs) or GitHub Audit Log Streaming.

Network Telemetry: VPC flow logs (AWS VPC Flow Logs, GCP VPC Flow Logs, Azure NSG Flow Logs) enabled on runner subnets and forwarded to the SIEM. DNS query logs from resolver infrastructure serving runner hosts. Full-packet capture capability (tcpdump) on runner host ethernet interfaces for targeted collection windows.

Cloud Provider Logs: AWS CloudTrail (all management and data events for the runner's IAM role and any roles it can assume), GCP Cloud Audit Logs, and Azure Activity Logs covering the window from March 1, 2026 through present. Container registry access logs (ECR, GHCR, Docker Hub) for push/pull events from runner credentials.

GitHub Audit Logs: GitHub organization audit log streaming enabled and forwarding to Datadog or the SIEM. Coverage required for: workflow runs, repository creation events, and secret access events for the period March 19–21, 2026.

5. Detection Signatures

The following SIGMA rule detects the malicious Trivy binary spawning unexpected child processes consistent with TeamPCP Cloud Stealer execution. Trivy is a scanner and should only spawn short-lived scanner child processes; the presence of python3, curl, wget, or sh as children is highly anomalous.

```yaml
title: TeamPCP Malicious Trivy Binary Spawning Unexpected Child Process
id: a4f1c2d3-8b5e-4a7f-9c0d-1e2f3a4b5c6d
status: experimental
description: Detects the Trivy vulnerability scanner spawning Python, curl, wget, or shell child processes, which is consistent with the TeamPCP-injected credential stealer executed via the malicious Trivy v0.69.4 supply chain compromise.
references:
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
author: 1898 & Co. Threat Hunt Team
date: 2026-03-20
tags:
- attack.initial_access
- attack.t1195.002
logsource:
category: process_creation
product: linux
detection:
selection:
ParentImage|endswith: '/trivy'
Image|endswith:
- '/python3'
- '/python'
- '/curl'
- '/wget'
- '/sh'
- '/bash'
condition: selection
falsepositives:
- None expected — trivy does not legitimately spawn Python or curl processes
level: critical
```
The following SIGMA rule detects DNS resolution of the TeamPCP typosquatted C2 domain. The domain aquasecurtiy\[.\]org is a deliberate misspelling of aquasecurity.org and has no legitimate use.

```bash
title: TeamPCP C2 Typosquatted Domain DNS Resolution
id: b5e2d3f4-9c6a-4b8e-0d1f-2a3b4c5d6e7f
status: stable
description: Detects DNS resolution of scan.aquasecurtiy[.]org or the root domain aquasecurtiy[.]org — a typosquatted domain used as primary C2 in the TeamPCP Trivy supply chain attack. The misspelling of aquasecurity (missing the 'i' in security) is the key discriminator.
references:
```

\- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release

```yaml
author: 1898 & Co. Threat Hunt Team
date: 2026-03-20
tags:
- attack.exfiltration
- attack.t1041
- attack.command_and_control
logsource:
category: dns_query
product: linux
detection:
selection:
QueryName|contains: 'aquasecurtiy'
condition: selection
falsepositives:
- None — this is a typosquatted domain with no legitimate use
level: critical
```
The following SIGMA rule detects outbound network connections from Python processes to the TeamPCP C2 IP address or Cloudflare Tunnel secondary C2. This rule targets Linux-based CI/CD runners where the credential stealer runs as a Python script.

```yaml
title: TeamPCP Cloud Stealer Outbound C2 Connection from Python Process
id: c6f3e4g5-0d7b-5c9f-1e2a-3b4c5d6e7f8a
status: experimental
description: Detects outbound network connections to the TeamPCP primary C2 IP (45.148.10.212) initiated by Python processes, consistent with the credential archive exfiltration step of the TeamPCP Cloud Stealer following compromise of aquasecurity/trivy-action.
references:
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
author: 1898 & Co. Threat Hunt Team
date: 2026-03-20
tags:
- attack.exfiltration
- attack.t1041
logsource:
category: network_connection
product: linux
detection:
selection_process:
Image|endswith:
- '/python3'
- '/python'
selection_dest:
DestinationIp: '45.148.10.212'
condition: selection_process and selection_dest
falsepositives:
- None expected for this specific IP
level: critical
```
The following SIGMA rule detects Python processes reading /proc/\<pid\>/mem files, which is the mechanism used by TeamPCP Cloud Stealer to extract in-memory GitHub Actions secrets from the Runner.Worker process.

```yaml
title: Python Process Reading /proc/pid/mem — Potential In-Memory Secret Extraction
id: d7a4f5h6-1e8c-6d0a-2f3b-4c5d6e7f8a9b
status: experimental
description: Detects Python processes opening files matching /proc/[0-9]+/mem or /proc/[0-9]+/maps, consistent with TeamPCP Cloud Stealer reading GitHub Actions Runner.Worker process memory to extract isSecret-flagged CI/CD secrets, bypassing platform-level secret masking.
references:
- https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release
author: 1898 & Co. Threat Hunt Team
date: 2026-03-20
tags:
- attack.credential_access
- attack.t1003.007
logsource:
category: file_event
product: linux
detection:
selection_process:
Image|endswith:
- '/python3'
- '/python'
selection_file:
TargetFilename|re: '^/proc/\[0-9\]+/(mem|maps)\$'
condition: selection_process and selection_file
falsepositives:
- Legitimate Python debugging tools (ptrace-based debuggers) that inspect process memory; suppress by monitoring host and known-good process name
level: high
```
Snort/Suricata rule detecting HTTPS connection attempts to the TeamPCP primary C2 IP, using TLS Server Name Indication (SNI) matching to catch the typosquatted domain even over TLS. This rule requires TLS inspection or JA3 fingerprinting capabilities at the network perimeter.

alert tls any any -\> 45.148.10.212 443 (

msg:"TeamPCP C2 TLS Connection to scan.aquasecurtiy.org - Supply Chain Attack C2";

tls.sni; content:"aquasecurtiy"; nocase;

flow:established,to_server;

threshold:type limit, track by_src, count 1, seconds 60;

classtype:trojan-activity;

sid:9001001; rev:1;

reference:url,stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release;

metadata:affected_product GitHub_Actions, attack_target CI_CD_Runner, deployment Perimeter, signature_severity Critical;

)

Snort/Suricata rule detecting DNS queries for the typosquatted aquasecurtiy domain, matching on the misspelled string regardless of subdomain prefix. Deploy on all DNS inspection points serving CI/CD runner infrastructure.

alert dns any any -\> any 53 (

msg:"TeamPCP Typosquatted C2 Domain DNS Query - aquasecurtiy.org";

dns.query; content:"aquasecurtiy"; nocase;

threshold:type limit, track by_src, count 1, seconds 300;

classtype:trojan-activity;

sid:9001002; rev:1;

reference:url,stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release;

metadata:affected_product GitHub_Actions, attack_target CI_CD_Runner, deployment DNS_Inspection, signature_severity Critical;

)

The following YARA rule targets the TeamPCP Cloud Stealer Python script on disk or in temporary storage. The rule combines three independent detection clusters: the in-memory secret extraction cluster (isSecret + Runner.Worker + /proc), the C2 communication cluster (typosquatted domain + exfiltration header), and the encryption cluster (RSA-OAEP + AES operations). Any one cluster is sufficient for a high-confidence hit. The /proc-based detection is Linux-specific and will not fire on Windows runners. False positives are highly unlikely given the specificity of isSecret + Runner.Worker as co-occurring strings outside of this malware context.

```yara
rule TeamPCP_Cloud_Stealer_Script {
```

meta:

description = "Detects TeamPCP Cloud Stealer Python credential harvesting script on disk; targets isSecret JSON key, Runner.Worker process name, /proc memory access, typosquatted C2 domain, and RSA/AES encryption library calls"

author = "1898 & Co. Threat Hunt Team"

date = "2026-03-20"

reference = "https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release"

hash = "dee4e6f155b95a80f60ca7c54106f878507cb359"

strings:

// In-memory secret extraction cluster

\$s1 = "isSecret" ascii // GitHub Actions secret JSON key — primary extraction target

\$s2 = "Runner.Worker" ascii // Target process name for /proc/pid/mem read

\$s3 = "/proc/" ascii // Linux proc filesystem access path

// C2 communication cluster

\$s4 = "aquasecurtiy" ascii nocase // Typosquatted C2 domain (note misspelling — no 'i' in security)

\$s5 = "X-Filename" ascii // Custom HTTP header used in exfiltration POST

\$s6 = "tpcp.tar.gz" ascii // Exfiltration archive filename

// Encryption cluster

\$s7 = "PKCS1_OAEP" ascii // RSA-OAEP encryption library (pycryptodome)

\$s8 = "AES.new" ascii // AES encryption initialization

// Actor identifier

\$s9 = "tpcp" ascii wide // Actor self-identifier

condition:

any of (\$s1, \$s2) and \$s3 or

\$s4 and (\$s5 or \$s6) or

\$s7 and \$s8 and (\$s1 or \$s9)

}

// File-system scan command:

```text
yara -r -p 4 TeamPCP_Cloud_Stealer_Script.yar /home /tmp /var /opt /root --exclude-dirs /proc --exclude-dirs /sys >> yara_hits_disk.txt 2>&1
```

The following YARA rule targets TeamPCP Cloud Stealer indicators in the memory of running Python processes. The rule is structured to match residual heap strings that would be present if the stealer executed or was loaded but not yet unloaded. The condition requires co-occurrence of the target secret key with either the target process name or the C2 domain to reduce false positives against general Python security tooling that may reference isSecret or /proc in isolation.

```yara
rule TeamPCP_Cloud_Stealer_Memory {
```

meta:

description = "Detects TeamPCP Cloud Stealer running in Python process memory; matches co-occurrence of GitHub Actions isSecret key, Runner.Worker target process name, C2 domain, or exfiltration artifacts in heap"

author = "1898 & Co. Threat Hunt Team"

date = "2026-03-20"

reference = "https://www.stepsecurity.io/blog/trivy-compromised-a-second-time---malicious-v0-69-4-release"

strings:

\$m1 = "isSecret" ascii // GitHub Actions in-memory secret JSON key

\$m2 = "Runner.Worker" ascii // Target process name as resident heap string

\$m3 = { 2F 70 72 6F 63 2F } // Hex for "/proc/" — proc filesystem path in memory

\$m4 = "tpcp.tar.gz" ascii // Exfiltration archive name resident in memory

\$m5 = "scan.aquasecurtiy" ascii // C2 domain in memory (note misspelling)

\$m6 = "X-Filename" ascii // Custom exfiltration HTTP header in memory

condition:

(\$m1 and \$m2) or

(\$m4 and \$m5) or

(\$m5 and \$m6) or

(\$m1 and \$m3 and \$m6)

}

// Memory scan command (Linux — requires root or ptrace_scope=0):

for pid in \$(pgrep python3); do sudo yara -p 2 TeamPCP_Cloud_Stealer_Memory.yar \$pid 2\>/dev/null && echo "HIT PID \$pid"; done \>\> yara_memory_hits.txt

// CrowdStrike RTR: deploy via Real Time Response custom script on affected hosts

The following YARA rule is the standing credential dump memory scan rule required for any hunt plan involving T1003.\* techniques. Although TeamPCP's primary credential harvesting mechanism targets Linux /proc memory (T1003.007), this rule is included to cover Windows runner environments where LSASS-based credential dumping tools may be used for post-compromise privilege escalation.

```yara
rule Credential_Dump_Tool_Memory_Artifacts {
```

meta:

description = "Standing rule — detects LSASS credential dumping tool artifacts in process memory. Covers Mimikatz, WCE, gsecdump, comsvcs MiniDump, and generic NtReadVirtualMemory+lsass patterns. Apply to Windows runner environments alongside TeamPCP-specific rules."

author = "1898 & Co. Threat Hunt Team"

date = "2026-03-20"

strings:

// Branch 1 — Mimikatz

\$mimi1 = "sekurlsa::logonpasswords" ascii nocase

\$mimi2 = "lsadump::sam" ascii nocase

\$mimi3 = "privilege::debug" ascii nocase

\$mimi4 = "mimikatz" ascii wide nocase

\$mimi5 = { 6D 69 6D 69 6B 61 74 7A } // "mimikatz" hex

// Branch 2 — Windows Credential Editor (WCE)

\$wce1 = "wce.exe" ascii nocase

\$wce2 = "lsass.exe" ascii nocase

// Branch 3 — gsecdump

\$gsec = "gsecdump" ascii nocase

// Branch 4 — comsvcs MiniDump

\$mini1 = "MiniDump" ascii

\$mini2 = "comsvcs" ascii nocase

\$mini3 = "lsass.exe" ascii nocase

// Branch 5 — Generic NtReadVirtualMemory + lsass catch-all

\$api1 = "NtReadVirtualMemory" ascii

\$api2 = "ReadProcessMemory" ascii

\$lsass = "lsass.exe" ascii nocase

\$tool = "sekurlsa" ascii nocase

condition:

(2 of (\$mimi\*)) or

(\$wce1 and \$wce2) or

\$gsec or

(\$mini1 and \$mini2 and \$mini3) or

((\$api1 or \$api2) and \$lsass and \$tool)

}

// Windows LSASS memory scan via YARA (requires SeDebugPrivilege):

// Get-Process lsass | ForEach-Object { & yara.exe -p 2 Credential_Dump_Tool_Memory_Artifacts.yar $_.Id 2\>\$null }

// CrowdStrike RTR: execute via Real Time Response with SeDebugPrivilege-enabled custom script

6. Indicators of Compromise

Network IOCs: Primary C2 IP: 45.148.10.212 (TECHOFF SRV LIMITED, AS208534, Amsterdam, Netherlands). Primary C2 domain: scan.aquasecurtiy\[.\]org (typosquat — note misspelled 'security'; resolves to 45.148.10.212). Secondary C2 (Cloudflare Tunnel): plug-tab-protective-relay.trycloudflare.com. Exfiltration protocol: HTTPS POST to port 443 with custom header X-Filename: tpcp.tar.gz. Pattern-based: any repository named tpcp-docs created in your GitHub organization during or after March 19, 2026.

File and Binary IOCs: Malicious trivy binary blob SHA: dee4e6f155b95a80f60ca7c54106f878507cb359 (GitHub blob in aquasecurity/trivy). Malicious aquasecurity/trivy-action commit: ddb9da4475c1cef7d5389062bdfdfbdbd1394648. Malicious aquasecurity/setup-trivy commit: 8afa9b9f9183b4e00c46e2b82d34047e3c177bd0. Safe aquasecurity/trivy-action SHA (v0.35.0 prior to compromise): 57a97c7e. Safe aquasecurity/setup-trivy release: v0.2.6. Exfiltration archive filename on disk: tpcp.tar.gz.

Actor and Malware IOCs: Threat actor alias: TeamPCP (also self-identifies as "teampcp"). Initial access bot account: hackerbot-claw. Malware family: TeamPCP Cloud Stealer (Python-based, hybrid RSA-4096 OAEP + AES-256-CBC encryption, /proc/pid/mem-based secret extraction, targets isSecret JSON objects in GitHub Actions Runner.Worker heap). Associated GitHub pattern: repositories named tpcp-docs created in victim organizations.

Behavioral IOCs: trivy process spawning python3, curl, wget, or sh as direct child. Python process opening /proc/\<pid\>/mem or /proc/\<pid\>/maps on a GitHub Actions runner. Outbound HTTPS POST from a CI/CD runner to a non-approved external IP with no corresponding build step. Creation of a public GitHub repository named tpcp-docs by a service account or automated runner token. DNS query for any domain containing the string aquasecurtiy (misspelling).

7. False Positive Baseline

The following known-good patterns should be suppressed during triage:

1. Trivy spawning sh or bash briefly for version checks or scan wrapper scripts shipped by legitimate versions v0.69.3 and earlier — verify the trivy binary SHA256 against the known-good manifest for v0.69.3 before escalating parent-child events.

2. Python3 processes reading /proc/self/environ in security scanning tools (such as Falco, Sysdig, and open-source security agents that enumerate their own runtime environment) — filter by process parent and command line to exclude scanner agents reading their own /proc paths.

3. DNS queries to api.github.com from Python processes used in legitimate GitHub API automation scripts within CI/CD pipelines — suppress if the Python process command line references a known-good automation workflow name and the parent is not trivy or Runner.Worker.

4. Outbound HTTPS from Python processes to cloud provider metadata endpoints (169.254.169.254, 169.254.170.2) — these are legitimate IMDSv2 queries in AWS-hosted runners; exclude by destination IP.

5. CriticalFile events on /proc/self/fd or /proc/self/status from legitimate process introspection tools — filter by TargetFileName pattern: only escalate /proc/\<numeric-pid\>/mem or /proc/\<numeric-pid\>/maps where the numeric PID does not match the querying process itself.

6. GitHub repository creation events for repositories named using project-specific naming conventions that coincidentally contain "tpcp" as an acronym — verify against the known repository naming standard before treating as an IOC.

7. Trivy v0.69.3 (or earlier) installations that appear as rare hashes in the frequency analysis — compare SHA256 against the published release checksums at github.com/aquasecurity/trivy/releases before treating low-count hashes as malicious.

8. Escalation Criteria

Escalate immediately to Incident Response upon confirmation of any of the following:

1. Any CrowdStrike NetworkConnectIP4 event showing an outbound connection to 45.148.10.212 from any host, regardless of process context.

2. Any DNS query for aquasecurtiy (misspelled domain) observed in any network telemetry source.

3. Any YARA hit on TeamPCP_Cloud_Stealer_Script against any file on any host, including temporary directories and container images.

4. Any YARA hit on TeamPCP_Cloud_Stealer_Memory against any running Python process on any CI/CD runner.

5. Any YARA hit on Credential_Dump_Tool_Memory_Artifacts against any process on a Windows runner host.

6. Discovery of a repository named tpcp-docs in the GitHub audit log, regardless of creator or visibility.

7. Confirmation that any GitHub Actions workflow referencing aquasecurity/trivy-action or aquasecurity/setup-trivy ran between 17:43 UTC and 23:13 UTC on March 19, 2026.

8. Identification of a trivy process hash that does not match published Aquasecurity release checksums for any version prior to v0.69.4.

9. Any cloud provider API call (AssumeRole, GetSecretValue, PutBucketPolicy, CreateUser) originating from an IP address that is not a known CI/CD runner IP range and using a service account ARN associated with runner credentials.

10\. Any Datadog Monitor alert from H1 through H4 firing with count greater than zero.

9. Hunt Completion Criteria and Reporting

The hunt is complete when: (a) all GitHub Actions workflow runs during the exposure window (17:43 UTC to 23:13 UTC on March 19, 2026) have been enumerated and checked against the compromised commit SHAs; (b) all CI/CD runner hosts that executed trivy or the compromised Actions during the exposure window have been identified and their network telemetry reviewed for C2 connections; (c) all GitHub organization repositories have been audited for tpcp-docs creation events; (d) cloud provider activity logs for all credentials accessible to runner workflows have been reviewed for unauthorized API calls; and (e) all YARA scans across runner hosts have returned clean results or all hits have been triaged.

The hunt completion report must contain: the complete list of workflow run IDs and associated runner hosts that executed during the exposure window; the outcome of hash verification for all trivy binaries found (matching or non-matching SHA256); a table of all outbound network connections from runner hosts to non-approved external destinations during the window; the result of cloud provider log review for each runner service account credential (no unauthorized calls, or a list of suspicious calls with timestamps and source IPs); YARA scan results (clean or hits with full file paths and process names); a definitive statement of whether any tpcp-docs repositories were found; and a recommended credential rotation status for each affected runner service account.

Escalation criteria in Section 8 that directly map to YARA rules: Items 3 and 4 require YARA hits on TeamPCP_Cloud_Stealer_Script and TeamPCP_Cloud_Stealer_Memory respectively; either hit should trigger immediate runner isolation and IR engagement. Item 5 requires a hit on Credential_Dump_Tool_Memory_Artifacts on a Windows runner and should trigger the same response.

10\. Advisory IoC Reference

| IOC Type | IOC |
|----|----|
| IP Address | 45.148.10.212 — TeamPCP primary C2; TECHOFF SRV LIMITED, AS208534, Amsterdam, Netherlands; used for HTTPS POST credential exfiltration |
| Domain | scan.aquasecurtiy\[.\]org — TeamPCP primary C2 domain; typosquat of aquasecurity.org (missing 'i' in security); resolves to 45.148.10.212 |
| Domain | plug-tab-protective-relay.trycloudflare.com — TeamPCP secondary C2 via Cloudflare Tunnel (fallback) |
| Domain | api.github.com — used by TeamPCP fallback mechanism to create tpcp-docs staging repository using stolen GITHUB_TOKEN |
| URL Pattern | https://scan.aquasecurtiy\[.\]org/\* — exfiltration endpoint; HTTPS POST with header X-Filename: tpcp.tar.gz |
| GitHub Blob SHA | dee4e6f155b95a80f60ca7c54106f878507cb359 — malicious trivy binary blob (aquasecurity/trivy repository) |
| Git Commit SHA | ddb9da4475c1cef7d5389062bdfdfbdbd1394648 — malicious aquasecurity/trivy-action commit; used for force-pushed tags v0.1.0–v0.35.0 (75 of 76 tags compromised) |
| Git Commit SHA | 8afa9b9f9183b4e00c46e2b82d34047e3c177bd0 — malicious aquasecurity/setup-trivy commit; deleted at 21:07 UTC March 19 2026 |
| Safe Commit SHA | 57a97c7e — safe aquasecurity/trivy-action SHA for v0.35.0 prior to compromise; pin workflows to this full SHA |
| Safe Release | aquasecurity/setup-trivy v0.2.6 — clean release published 21:43 UTC March 19 2026; use this or pin to SHA |
| File Name | tpcp.tar.gz — exfiltration archive filename; AES-256-CBC + RSA-4096 OAEP encrypted credential bundle |
| HTTP Header | X-Filename: tpcp.tar.gz — custom header on TeamPCP exfiltration HTTPS POST requests |
| GitHub Repo Pattern | tpcp-docs — attacker-created public repository in victim GitHub org used as fallback credential staging location |
| Actor | TeamPCP (alias: teampcp) — supply chain threat actor; responsible for both February 28 and March 19 2026 Trivy compromises; coordinated spam bot campaign (17 accounts) on March 20 2026 |
| Actor | hackerbot-claw — GitHub bot account used as initial access vector in February 28 2026 pull_request_target exploitation |
| Malware | TeamPCP Cloud Stealer — Python-based CI/CD credential harvesting malware; harvests /proc/\*/environ and reads Runner.Worker /proc/\<pid\>/mem to extract isSecret JSON secrets; hybrid RSA-4096 OAEP + AES-256-CBC encryption; exfiltrates to scan.aquasecurtiy\[.\]org or creates tpcp-docs staging repo |
| Behavioral | trivy process spawning python3, curl, wget, or sh as a direct child process |
| Behavioral | Python process opening /proc/\<numeric-pid\>/mem or /proc/\<numeric-pid\>/maps on a GitHub Actions runner |
| Behavioral | Outbound HTTPS POST from CI/CD runner host to non-approved external IP immediately after trivy execution |
| Behavioral | GitHub repository named tpcp-docs created by a runner service account or automated token |
| Behavioral | DNS query for any domain containing the string aquasecurtiy (misspelling — missing 'i' in security) |
| Behavioral | GitHub Actions workflow run referencing aquasecurity/trivy-action or aquasecurity/setup-trivy by mutable tag between 17:43 UTC and 23:13 UTC on March 19 2026 |
| Behavioral | Cloud provider API call (AssumeRole, GetSecretValue, CreateUser, PutBucketPolicy) from a non-runner IP using runner service account credentials after March 19 2026 |
