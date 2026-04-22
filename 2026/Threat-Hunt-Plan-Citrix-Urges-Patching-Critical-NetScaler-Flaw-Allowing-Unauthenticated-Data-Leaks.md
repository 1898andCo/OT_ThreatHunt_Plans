# Threat Hunt Plan: CVE-2026-3055 & CVE-2026-4368 — Citrix NetScaler Unauthenticated Memory Leakage and Session Hijacking

> Date: 2026-03-25 | Revision: 1.0

# Hunt Objective and Scope

This hunt targets exploitation of CVE-2026-3055, a critical (CVSS v4.0 9.3) out-of-bounds read in Citrix NetScaler ADC and NetScaler Gateway configured as SAML Identity Providers, and CVE-2026-4368, a high-severity (CVSS v4.0 7.7) race condition affecting appliances configured as gateway or AAA virtual servers. The objective is to determine whether any NetScaler appliance in the environment has been targeted for unauthenticated memory leakage or has exhibited session mix-up conditions that could indicate exploitation or unauthorized session access.

The environment in scope includes all on-premises NetScaler ADC and NetScaler Gateway appliances running affected builds (14.1 before 14.1-66.59, 13.1 before 13.1-62.23, or 13.1-FIPS/NDcPP before 13.1-37.262), as well as perimeter firewalls and web application firewalls fronting those appliances, Citrix-managed authentication infrastructure, and associated identity provider integrations. The hunt time window covers the 30 days preceding the advisory publication date (2026-02-23 through 2026-03-25) to capture any pre-disclosure exploitation, and ongoing until all affected appliances are confirmed patched.

# Hypotheses and Hunt Procedures

## Hypothesis 1

An unauthenticated threat actor has sent malformed SAML authentication requests to a NetScaler appliance configured as a SAML IDP, triggering out-of-bounds memory reads and exfiltrating sensitive in-memory data via CVE-2026-3055.

### MITRE ATT&CK

Initial Access | T1190 — Exploit Public-Facing Application | An attacker targeting a publicly accessible NetScaler SAML IDP endpoint requires no credentials and leaves minimal authentication artifacts, making web-layer and appliance-level telemetry the primary detection surface.

### Collection Queries

#### CrowdStrike Falcon FQL — Network connections to NetScaler SAML IDP port (data collection)

```text
#event_simpleName = "NetworkReceiveAcceptIP4"
| RemotePort = "443"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]
)
| FileName = /nsaad|nscollect|ns/i
| table([ComputerName, RemoteAddressIP4, RemotePort, FileName, CommandLine, ParentBaseFileName])
#### CrowdStrike Falcon FQL — Large or anomalous outbound transfers from NetScaler hosts (data exfil collection)
#event_simpleName = "NetworkConnectIP4"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,ParentBaseFileName]
)
| FileName = /ns/i
| table([ComputerName, RemoteAddressIP4, RemotePort, FileName, CommandLine])
```

#### BPF — Capture inbound SAML authentication traffic on NetScaler SAML IDP interface

sudo tcpdump -i eth0 -w /tmp/saml_inbound\_%Y%m%d\_%H%M%S.pcap -G 3600 -C 500 \\

"tcp port 443 and (tcp\[((tcp\[12:1\] & 0xf0) \>\> 2):4\] = 0x504f5354)"

#### BPF — Rolling capture of all inbound TCP sessions from non-RFC1918 addresses

sudo tcpdump -i eth0 -w /tmp/netscaler_extern\_%Y%m%d\_%H%M%S.pcap -G 1800 -C 200 \\

"tcp and not (src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)"

#### Datadog Log Search — Inbound HTTPS requests to SAML IDP endpoint with HTTP 200/500 responses

```text
source:citrix @url:\*/saml/\* (status:error OR @http.status_code:[500 TO 599]) -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// time range: 2026-02-23T00:00Z to current
```
#### Datadog Log Search — NetScaler application-level error events (memory/access violations)

```text
source:citrix message:("out-of-bounds" OR "memory read" OR "segfault" OR "core dump" OR "signal 11")
// time range: 2026-02-23T00:00Z to current
// Note: Requires NetScaler nslog or syslog forwarded to Datadog. If not forwarded, use source:syslog host:<netscaler-hostname> instead.
#### Datadog Live Process Monitoring (Infrastructure \> Processes — NOT a log source)
command:ns user:root
// Free text search: "nsaad" OR "nscollect" to identify anomalous NetScaler daemon activity
```

#### Windows Event IDs to collect (on Windows-based authentication infrastructure integrated with NetScaler SAML IDP)

Event ID 4625: Failed logon (SAML assertion failures surfacing as authentication rejections)

Event ID 1102: Audit log cleared (potential evidence tampering post-exploitation)

Event ID 4648: Logon with explicit credentials (lateral movement after credential extraction)

Collection command:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625,4648,1102; StartTime=(Get-Date).AddDays(-30)} |
Select-Object TimeCreated, Id, Message |
Export-Csv -Path C:\hunt\saml_auth_events.csv -NoTypeInformation
```

#### YARA — File-system scan for SAML response capture tools or memory dump artifacts on NetScaler hosts

```text
yara -r /etc/yara/saml_exploit_artifacts.yar /var/nslog/ /tmp/ /var/tmp/ >> /tmp/yara_saml_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Frequency analysis: source IPs generating anomalous SAML endpoint request bursts (rarity of request rates)
#event_simpleName = "NetworkReceiveAcceptIP4"
| RemotePort = "443"
| groupBy([ComputerName, RemoteAddressIP4], function=count(), limit=100000)
| sort(\_count, order=desc, limit=100)
#### CrowdStrike Falcon FQL — Detect unexpected child process spawning from NetScaler daemons (post-exploitation)
#event_simpleName = "ProcessRollup2"
| ParentBaseFileName = /nsaad|nsmgmt|nsnetsvc|ns/i
| FileName = /sh|bash|python|perl|nc|curl|wget/i
| table([ComputerName, ParentBaseFileName, FileName, CommandLine, AuthenticationId])
```

#### Wireshark display filter — Identify malformed SAML AuthnRequest payloads or oversized SAML bodies

http.request.method == "POST" && http.request.uri contains "/saml" && http.content_length \> 8192

```text
tshark CLI equivalent:
tshark -r /tmp/saml_inbound\_\*.pcap \\
-Y 'http.request.method == "POST" && http.request.uri contains "/saml" && http.content_length \> 8192' \\
-T fields -e frame.time -e ip.src -e http.content_length -e http.request.uri \\
\>\> /tmp/saml_malformed_requests.txt
#### Wireshark display filter — Detect SAML responses with embedded binary/non-XML content indicative of memory leakage
http.response.code == 200 && http.content_type contains "saml" && data.len \> 65536
tshark CLI equivalent:
tshark -r /tmp/saml_inbound\_\*.pcap \\
```

-Y 'http.response.code == 200 && data.len \> 65536' \\

-T fields -e frame.time -e ip.dst -e data.len \\

\>\> /tmp/saml_large_responses.txt

#### Datadog Log Analytics — Top external IPs by SAML endpoint request volume (Table view)

```text
source:citrix @url:\*/saml/\*
// Table view; group by @network.client.ip; sort descending by count; time range: 2026-02-23T00:00Z to current
```

#### Datadog Log Analytics — Timeseries of NetScaler error rate spikes (potential exploit activity)

```text
source:citrix status:error
// Timeseries view; group by @http.status_code; time range: 2026-02-23T00:00Z to current
```
#### Datadog Audit Trail — API key or integration changes coinciding with NetScaler anomalies

```text
source:datadog @evt.category:api_key_management @evt.name:created
// Access via Datadog Admin > Audit Trail; time range: 2026-02-23T00:00Z to current
```

#### Datadog Monitor — Alert on spike in NetScaler error responses from external IPs

```text
Type: Log Alert
Query: source:citrix status:error -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
Evaluation window: last 5 minutes
Alert condition: count > 50
```
#### Message: "ALERT: Elevated NetScaler error rate from external source — potential CVE-2026-3055 exploitation attempt. Immediate investigation required. @security-oncall"

Prerequisites: NetScaler nslog or syslog must be forwarded to Datadog. Citrix integration or custom syslog pipeline required.

Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### PowerShell — Hunt for failed SAML-related authentication events on integrated Windows authentication servers

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-30)} |
Where-Object {$\_.Message -match 'SAML|Kerberos|NTLM'} |
Select-Object TimeCreated, @{N='AccountName';E={$\_.Properties[5].Value}},
@{N='FailureReason';E={$\_.Properties[8].Value}},
@{N='SourceIP';E={$\_.Properties[19].Value}} |
Export-Csv -Path C:\hunt\failed_saml_auth.csv -NoTypeInformation
```

#### YARA — Memory scan for in-memory SAML exploit tooling on NetScaler host processes

```text
yara -p $(pgrep nsaad) /etc/yara/saml_exploit_artifacts.yar
// Note: CrowdStrike Falcon RTR can execute YARA remotely: RTR > Run Script > yara -p <pid> rules.yar
```

## Hypothesis 2

A threat actor has exploited CVE-2026-4368 to cause session confusion on a NetScaler gateway, enabling unauthorized access to an authenticated user session.

### MITRE ATT&CK

Lateral Movement | T1563 — Remote Service Session Hijacking | Race condition-induced session mix-up in a gateway or AAA server allows an attacker to inherit another user's authenticated session, effectively hijacking access to enterprise applications without credential theft.

### Collection Queries

#### CrowdStrike Falcon FQL — Collect all authentication-related process events on NetScaler-adjacent hosts

```text
#event_simpleName = "UserLogon"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]), limit=100000)},
field=[aid,ContextProcessId], key=[aid,TargetProcessId],
include=[ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]
)
| table([ComputerName, UserName, AuthenticationId, FileName, CommandLine, ParentBaseFileName])
#### CrowdStrike Falcon FQL — Collect session-related DNS queries from gateway-connected endpoints
#event_simpleName = "DnsRequest"
| DomainName = /netscaler|citrix|vpn|gateway|aaa/i
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)},
field=[aid,ContextProcessId], key=[aid,TargetProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]
)
| table([ComputerName, DomainName, IpAddress, RequestType, FileName, CommandLine])
```

#### BPF — Capture gateway SSL VPN session establishment traffic

sudo tcpdump -i eth0 -w /tmp/gateway_sessions\_%Y%m%d\_%H%M%S.pcap -G 1800 -C 500 \\

"tcp port 443 and not (src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)"

#### BPF — Capture DTLS traffic (used by Citrix ICA/HDX sessions)

sudo tcpdump -i eth0 -w /tmp/dtls_sessions\_%Y%m%d\_%H%M%S.pcap -G 1800 -C 200 \\

"udp port 443"

#### Datadog Log Search — Session cookie reuse from multiple distinct IPs (session hijacking indicator)

```text
source:citrix @http.headers.cookie:\* -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// time range: 2026-02-23T00:00Z to current
// Note: Requires Citrix access logs with cookie header logging enabled. If unavailable, use source:syslog host:<netscaler-hostname> message:("session" OR "cookie") as fallback.
#### Datadog Log Search — NetScaler AAA authentication events with unexpected session transitions
source:citrix message:("session mixup" OR "session mismatch" OR "invalid session" OR "race" OR "concurrent session")
// time range: 2026-02-23T00:00Z to current
#### Datadog Live Process Monitoring (Infrastructure \> Processes — NOT a log source)
command:nsconmsg user:root
// Identifies NetScaler connection message daemon activity; free text search: "nsvpnvserver" OR "nsaaa"
```

#### Windows Event IDs to collect (on downstream Windows systems accessed via NetScaler gateway)

Event ID 4624: Successful logon (baseline session establishment from gateway source IPs)

Event ID 4634: Logoff (session termination patterns; mismatched logon/logoff pairs indicate confusion)

Event ID 4776: NTLM credential validation (pass-through authentication via NetScaler gateway)

Event ID 4768: Kerberos TGT requests (session initiation from gateway-connected endpoints)

Collection command:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4634,4776,4768; StartTime=(Get-Date).AddDays(-30)} |
Select-Object TimeCreated, Id, @{N='Account';E={$\_.Properties[5].Value}},
@{N='LogonType';E={$\_.Properties[8].Value}},
@{N='SourceIP';E={$\_.Properties[18].Value}} |
Export-Csv -Path C:\hunt\gateway_logon_events.csv -NoTypeInformation
```

#### YARA — File-system scan for session token capture tools or proxy/interception software on NetScaler hosts

```text
yara -r /etc/yara/session_hijack_artifacts.yar /tmp/ /var/tmp/ /var/nslog/ >> /tmp/yara_session_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Detect same session cookie or token used from multiple distinct source IPs (session mix-up indicator)
#event_simpleName = "NetworkReceiveAcceptIP4"
| groupBy([ComputerName, RemoteAddressIP4], function=count(), limit=100000)
| sort(\_count, order=desc, limit=100)
#### CrowdStrike Falcon FQL — Identify short-duration session bursts (typical of race condition triggering)
#event_simpleName = "NetworkConnectIP4"
| RemotePort = "443"
| groupBy([ComputerName, RemoteAddressIP4], function=count(), limit=100000)
| sort(\_count, order=desc, limit=50)
```

#### Wireshark display filter — Detect TLS session resumption anomalies (session ID reuse from multiple IPs)

ssl.handshake.type == 2 && ssl.handshake.session_id_length \> 0

```text
tshark CLI equivalent:
tshark -r /tmp/gateway_sessions\_\*.pcap \\
-Y 'ssl.handshake.type == 2 && ssl.handshake.session_id_length \> 0' \\
-T fields -e frame.time -e ip.src -e ssl.handshake.session_id \\
| sort -k3 | uniq -d -f2 \\
\>\> /tmp/tls_session_reuse.txt
#### Wireshark display filter — Detect concurrent active TLS sessions from the same session ID (session confusion)
ssl.record.content_type == 23 && ip.src != ip.dst
tshark CLI equivalent:
tshark -r /tmp/gateway_sessions\_\*.pcap \\
```

-Y 'ssl.record.content_type == 23' \\

-T fields -e frame.time -e ip.src -e ip.dst -e ssl.record.length \\

\>\> /tmp/tls_active_sessions.txt

#### Datadog Log Analytics — Sessions per source IP over time (Table view for session distribution anomalies)

```text
source:citrix @http.headers.cookie:\*
// Table view; group by @network.client.ip; time range: 2026-02-23T00:00Z to current
#### Datadog Log Analytics — Timeseries of authentication events (spike indicates race condition activity)
source:citrix message:("session" OR "auth" OR "logon")
// Timeseries view; group by @http.status_code; time range: 2026-02-23T00:00Z to current
#### Datadog CloudTrail — Detect API calls made from unexpected IPs following NetScaler session establishment
source:cloudtrail @evt.name:(AssumeRole OR GetCredentials OR ListBuckets) -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// Analytics: Table view; group by @network.client.ip, @userIdentity.arn; time range: 2026-02-23T00:00Z to current
#### Datadog Audit Trail — Investigate user management changes occurring after anomalous gateway sessions
source:datadog @evt.category:user_management @evt.name:user.login
// Access via Datadog Admin > Audit Trail; time range: 2026-02-23T00:00Z to current
#### Datadog Monitor — Alert on authentication session anomalies from gateway source IPs
Type: Log Alert
Query: source:citrix message:("session mixup" OR "invalid session" OR "race" OR "concurrent session")
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: Potential CVE-2026-4368 session confusion event detected on NetScaler gateway. Immediate session audit and investigation required. @security-oncall"
```

Prerequisites: NetScaler syslog with detailed session logging must be forwarded to Datadog. Enable verbose session logging via Citrix CLI before deploying this monitor.

Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### PowerShell — Hunt for Windows logon sessions originating from NetScaler gateway IPs with mismatched user context

\$gatewayIPs = @("10.0.0.1","192.168.1.1") \# Replace with actual NetScaler gateway IPs

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-30)} |
Where-Object {$\_.Properties[18].Value -in $gatewayIPs} |
Select-Object TimeCreated,
@{N='Account';E={$\_.Properties[5].Value}},
@{N='LogonType';E={$\_.Properties[8].Value}},
@{N='SourceIP';E={$\_.Properties[18].Value}} |
```

Group-Object Account |

```text
Where-Object {($\_.Group | Select-Object -ExpandProperty SourceIP | Sort-Object -Unique).Count -gt 1} |
Export-Csv -Path C:\hunt\gateway_session_anomalies.csv -NoTypeInformation
```

#### YARA — Memory scan for session token injection tooling resident in NetScaler daemon processes

```text
yara -p $(pgrep nsvpnd) /etc/yara/session_hijack_artifacts.yar
// Note: CrowdStrike RTR can execute YARA on remote hosts via RTR > Run Script
```

## Hypothesis 3

A threat actor is performing reconnaissance or exploitation staging against NetScaler management interfaces following initial memory leakage from CVE-2026-3055, using extracted credentials or session tokens to pivot to internal resources.

### MITRE ATT&CK

Lateral Movement | T1021.001 — Remote Services: Remote Desktop Protocol | Following credential or session token extraction via CVE-2026-3055 memory leakage, an attacker may use harvested authentication material to move laterally to Windows systems accessible via the NetScaler gateway or to management interfaces of downstream OT/ICS infrastructure.

### Collection Queries

#### CrowdStrike Falcon FQL — Collect outbound RDP connections from hosts adjacent to NetScaler (lateral movement collection)

```text
#event_simpleName = "NetworkConnectIP4"
| RemotePort = "3389"
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]
)
| table([ComputerName, RemoteAddressIP4, RemotePort, FileName, CommandLine, ParentBaseFileName])
#### CrowdStrike Falcon FQL — Credential access: LSASS memory read attempts on hosts accessible via NetScaler
#event_simpleName = "ProcessRollup2"
| FileName = /mimikatz|procdump|rundll32|comsvcs/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, AuthenticationId])
```

#### BPF — Capture RDP and WinRM lateral movement from NetScaler-adjacent segments

sudo tcpdump -i eth1 -w /tmp/lateral_rdp\_%Y%m%d\_%H%M%S.pcap -G 1800 -C 200 \\

"tcp port 3389 or tcp port 5985 or tcp port 5986"

#### Datadog Log Search — Remote execution events on Windows hosts accessed via NetScaler gateway

```text
source:windows message:("psexec" OR "wmiexec" OR "winrm" OR "invoke-command" OR "New-PSSession")
// time range: 2026-02-23T00:00Z to current
#### Datadog Live Process Monitoring (Infrastructure \> Processes — NOT a log source)
command:mstsc user:administrator
// Identify RDP client executions; free text: "psexec" OR "wmic" for lateral movement staging
```

#### Windows Event IDs to collect

Event ID 4648: Logon with explicit credentials (pass-the-hash or harvested credential reuse)

Event ID 4688: Process creation with full command line (lateral movement tool execution)

Event ID 7045: New service installed (persistence after lateral movement)

Event ID 4698: Scheduled task created (persistence mechanism)

Collection command:

```text
Get-WinEvent -FilterHashtable @{LogName='Security','System','Microsoft-Windows-TaskScheduler/Operational'; Id=4648,4688,7045,4698; StartTime=(Get-Date).AddDays(-30)} |
Select-Object TimeCreated, Id, Message |
Export-Csv -Path C:\hunt\lateral_movement_events.csv -NoTypeInformation
```

#### YARA — File-system scan for lateral movement staging tools on hosts accessible via NetScaler gateway

```text
yara -r /etc/yara/credential_dump_tools.yar C:\Windows\Temp\\ C:\Users\Public\\ C:\ProgramData\\ >> C:\hunt\yara_lateral_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Rarity analysis: hosts with first-time RDP connections from NetScaler gateway IPs
#event_simpleName = "NetworkConnectIP4"
| RemotePort = "3389"
| groupBy([ComputerName, RemoteAddressIP4], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
#### CrowdStrike Falcon FQL — Timeline correlation: credential access tools launched within 10 minutes of NetScaler authentication events
#event_simpleName = "ProcessRollup2"
| FileName = /mimikatz|procdump|lsass|comsvcs/i
| table([ComputerName, FileName, CommandLine, ParentBaseFileName, ContextTimeStamp])
```

#### Wireshark display filter — Detect RDP authentication with NTLM (indicative of harvested credential reuse)

rdp.negotiation_request_flags && ntlmssp.auth.username

```text
tshark CLI equivalent:
tshark -r /tmp/lateral_rdp\_\*.pcap \\
-Y 'ntlmssp.auth.username' \\
-T fields -e frame.time -e ip.src -e ip.dst -e ntlmssp.auth.username \\
\>\> /tmp/rdp_ntlm_auth.txt
#### Wireshark display filter — Detect NTLM relay or pass-the-hash patterns (multiple rapid NTLM authentications from single IP)
ntlmssp.messagetype == 3 && ip.src == ip.dst
tshark CLI equivalent:
tshark -r /tmp/lateral_rdp\_\*.pcap \\
```

-Y 'ntlmssp.messagetype == 3' \\

-T fields -e frame.time -e ip.src -e ntlmssp.auth.username -e ntlmssp.auth.domain \\

```text
| sort -k3 | uniq -d -f2 \\
```
\>\> /tmp/ntlm_relay_candidates.txt

#### Datadog Log Analytics — Top accounts used for RDP or WinRM access from gateway IPs

```text
source:windows message:("4648" OR "explicit credentials")
// Table view; group by @usr.name; time range: 2026-02-23T00:00Z to current
#### Datadog CloudTrail — Cloud API access from IPs matching NetScaler gateway external addresses
source:cloudtrail @evt.name:(AssumeRole OR ConsoleLogin OR CreateAccessKey) -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// Analytics: Table view; group by @network.client.ip, @userIdentity.arn; time range: 2026-02-23T00:00Z to current
#### Datadog Monitor — Alert on credential dump tool execution on gateway-adjacent hosts
Type: Log Alert
Query: source:windows message:("mimikatz" OR "procdump" OR "comsvcs" OR "MiniDump" OR "sekurlsa")
Evaluation window: last 5 minutes
Alert condition: count > 0
```

#### Message: "ALERT: Credential dump tool activity detected on host — potential post-exploitation following NetScaler CVE-2026-3055 exploitation. Immediate IR engagement required. @security-oncall"

Prerequisites: Windows Security event logs (Event ID 4688 with command line logging) must be forwarded to Datadog. PowerShell Script Block Logging (Event ID 4104) forwarding recommended.

Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### PowerShell — Hunt for lateral movement from gateway-adjacent hosts using pass-the-hash indicators

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4648; StartTime=(Get-Date).AddDays(-30)} |
Where-Object {$\_.Properties[12].Value -match '^(10|172\\1[6-9]|172\\2[0-9]|172\\3[01]|192\\168\\)' -eq $false} |
Select-Object TimeCreated,
@{N='SubjectAccount';E={$\_.Properties[1].Value}},
@{N='TargetAccount';E={$\_.Properties[5].Value}},
@{N='TargetServer';E={$\_.Properties[9].Value}},
@{N='SourceIP';E={$\_.Properties[12].Value}} |
Export-Csv -Path C:\hunt\explicit_cred_logons.csv -NoTypeInformation
```

#### YARA — Memory scan for Mimikatz or credential theft tooling in active processes

```text
Get-Process | ForEach-Object {
```

\$pid = $_.Id

& yara C:\yara_rules\Credential_Dump_Tool_Memory_Artifacts.yar -p \$pid 2\>\$null |

ForEach-Object { Write-Output "PID \$pid: \$\_" }

} | Out-File C:\hunt\yara_cred_memory.txt

// Note: CrowdStrike RTR can execute YARA on remote hosts: RTR \> Run Script \> yara -p \<pid\> rules.yar

## Hypothesis 4

An automated scanning infrastructure or exploit framework has enumerated NetScaler SAML IDP and gateway endpoints at scale, generating anomalous authentication request volumes that are distinguishable from legitimate traffic patterns.

### MITRE ATT&CK

Reconnaissance | T1595.002 — Active Scanning: Vulnerability Scanning | Automated scanners and exploit frameworks targeting CVE-2026-3055 will generate high volumes of SAML authentication requests with anomalous payload structures, detectable via frequency analysis and BPF rate capture.

### Collection Queries

#### CrowdStrike Falcon FQL — High-frequency inbound connection collection for NetScaler hosts

```text
#event_simpleName = "NetworkReceiveAcceptIP4"
| RemotePort = "443"
| groupBy([ComputerName, RemoteAddressIP4], function=count(), limit=100000)
| sort(\_count, order=desc, limit=100)
```

#### BPF — Rate-capture for SYN flood or connection burst detection

sudo tcpdump -i eth0 -w /tmp/scan_detection\_%Y%m%d\_%H%M%S.pcap -G 600 -C 100 \\

"tcp\[tcpflags\] & (tcp-syn) != 0 and not (src net 10.0.0.0/8 or src net 172.16.0.0/12 or src net 192.168.0.0/16)"

#### Datadog Log Search — High-frequency SAML endpoint requests by source IP (scanner fingerprint)

```text
source:citrix @url:\*/saml/\* -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// time range: 2026-02-23T00:00Z to current
// Note: Requires Citrix access logs forwarded to Datadog. Data source gap: if Citrix logs are not forwarded, use WAF or firewall logs as fallback: source:firewall @destination.port:443.
#### Datadog Live Process Monitoring (Infrastructure \> Processes — NOT a log source)
command:nshttp user:root
// Identify NetScaler HTTP processing daemon activity during suspected scan windows
```

#### Windows Event IDs to collect (perimeter firewall / WAF Windows-based management)

Event ID 5156: Windows Filtering Platform connection permitted (high-volume inbound to NetScaler)

Event ID 5157: Windows Filtering Platform connection blocked (scan traffic blocked at perimeter)

Collection command:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156,5157; StartTime=(Get-Date).AddDays(-7)} |
Where-Object {$\_.Properties[5].Value -eq '443'} |
Select-Object TimeCreated, @{N='SourceIP';E={$\_.Properties[3].Value}},
@{N='DestPort';E={$\_.Properties[5].Value}},
@{N='Direction';E={$\_.Properties[7].Value}} |
Export-Csv -Path C:\hunt\netscaler_firewall_events.csv -NoTypeInformation
```

#### YARA — Scan for exploit framework staging files (e.g., Metasploit modules, nuclei templates) on NetScaler hosts

```text
yara -r /etc/yara/exploit_framework_artifacts.yar /tmp/ /var/tmp/ /root/ >> /tmp/yara_scanner_hits.txt
### Analysis Queries
#### CrowdStrike Falcon FQL — Top source IPs by inbound connection count to NetScaler (most active scanners)
#event_simpleName = "NetworkReceiveAcceptIP4"
| RemotePort = "443"
| top([RemoteAddressIP4, ComputerName], limit=50)
```

#### Wireshark display filter — Detect HTTP user-agents associated with vulnerability scanners and exploit frameworks

http.user_agent matches "(nuclei|nmap|masscan|shodan|zgrab|dirbuster|nikto|metasploit|python-requests/2|Go-http-client)"

```text
tshark CLI equivalent:
tshark -r /tmp/scan_detection\_\*.pcap \\
```

-Y 'http.user_agent matches "(nuclei|nmap|masscan|shodan|zgrab|dirbuster|nikto|metasploit|python-requests/2|Go-http-client)"' \\

-T fields -e frame.time -e ip.src -e http.user_agent -e http.request.uri \\

\>\> /tmp/scanner_user_agents.txt

#### Datadog Log Analytics — Timeseries of inbound SAML request volume (spike detection for exploit waves)

```text
source:citrix @url:\*/saml/\*
// Timeseries view; group by @network.client.ip; time range: 2026-02-23T00:00Z to current
#### Datadog Monitor — Alert on scanner-level request volumes to NetScaler SAML endpoint
Type: Log Alert
Query: source:citrix @url:\*/saml/\* -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
Evaluation window: last 1 minute
Alert condition: count > 200
```

#### Message: "ALERT: Anomalous SAML endpoint request volume detected — potential CVE-2026-3055 scanning or exploitation. Block source IPs at perimeter and initiate investigation. @security-oncall"

Prerequisites: Citrix access logs or WAF logs must be forwarded to Datadog with @url field populated.

Create via: Monitors \> New Monitor \> Log Alert OR POST /api/v1/monitors

#### PowerShell — Identify source IPs generating high-volume firewall connection events to NetScaler

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-7)} |
Where-Object {$\_.Properties[5].Value -eq '443'} |
```

Group-Object {$_.Properties\[3\].Value} |

Sort-Object Count -Descending |

```text
Select-Object -First 50 Name, Count |
Export-Csv -Path C:\hunt\top_source_ips.csv -NoTypeInformation
```

#### YARA — Memory scan for scanner or exploit framework tooling on NetScaler and adjacent hosts

```text
yara -p $(pgrep -f "python|ruby|go") /etc/yara/exploit_framework_artifacts.yar
// Note: CrowdStrike RTR can execute YARA on remote hosts; enumerate process IDs first via RTR > Run Script > ps aux
```

# Threat Actor Profile

The primary threat actors likely to exploit CVE-2026-3055 and CVE-2026-4368 fall into three categories based on historical NetScaler exploitation patterns.

Ransomware operators represent the most immediate and operationally significant threat. Groups including those that exploited CitrixBleed (CVE-2023-4966) have demonstrated both the technical capability and economic motivation to rapidly weaponize NetScaler vulnerabilities. These actors typically operate with moderate to high technical sophistication, targeting NetScaler appliances as initial access vectors to harvest session tokens, pivot to enterprise networks, and deploy ransomware payloads. Their access path for CVE-2026-3055 follows a pattern of mass Internet scanning to identify SAML IDP endpoints, exploitation for memory data extraction, credential harvesting from extracted memory contents, and subsequent lateral movement using legitimate credentials.

#### Nation-state and advanced persistent threat actors represent the most sophisticated targeting risk. Groups with a historical interest in perimeter authentication infrastructure — including actors linked to campaigns against energy, utilities, and critical infrastructure organizations — may leverage CVE-2026-3055 to silently extract session tokens and authentication material from NetScaler appliances serving as remote access gateways for OT-adjacent networks. These actors typically exhibit low-and-slow exploitation patterns designed to avoid detection, and may use CVE-2026-4368 session confusion as a secondary technique to access privileged management sessions without generating credential-based detections.

Opportunistic financially motivated actors and initial access brokers represent a broad third category. Following prior disclosures, NetScaler appliances were indexed by scanning services such as Shodan and Censys within hours, and exploit code was incorporated into frameworks shortly after proof-of-concept publication. Initial access brokers monetize NetScaler footholds by selling access to ransomware affiliates, espionage operators, and other buyers. Their TTPs include automated scanning using tools such as Nuclei or Metasploit, exploit execution targeting the SAML IDP endpoint, and rapid sale or use of harvested session material or credentials.

# Data Sources Required

***Network:*** Full packet capture (PCAP) from the external interface of all NetScaler appliances; NetFlow or IPFIX from perimeter firewalls; web application firewall logs with full URI and payload logging enabled; DNS query logs from recursive resolvers serving NetScaler-adjacent network segments.

***Endpoint:*** CrowdStrike Falcon telemetry from all Windows hosts accessible via NetScaler gateway (ProcessRollup2, UserLogon, NetworkConnectIP4, DnsRequest event streams); Windows Security Event Log (Event IDs 4624, 4625, 4648, 4688, 4698, 7045, 4776, 4768, 1102); PowerShell Script Block Logging (Event ID 4104) on all systems; Sysmon (Event IDs 1, 3, 7, 11, 22) if deployed.

NetScaler Appliance: Native nslog and syslog output (authentication events, error logs, SSL handshake events, session lifecycle events); Citrix ADM (Application Delivery Management) if deployed, for appliance-level telemetry aggregation; SNMP traps from NetScaler appliances for high-level availability and error rate monitoring.

***OT/ICS:*** If NetScaler serves as a remote access gateway for OT network segments, collect historian access logs, SCADA alarm logs, and OT asset management platform (Claroty, Dragos, or Nozomi) alerts correlated with NetScaler authentication events. SNMP polling of switches on the OT-facing NetScaler interface for unusual traffic volumes.

Cloud: CloudTrail logs (if cloud infrastructure is accessed via NetScaler gateway), Datadog Cloud SIEM integration for cross-platform correlation.

# Detection Signatures

This rule detects processes spawning shells or download utilities from NetScaler daemon parent processes, which would indicate post-exploitation command execution on a compromised NetScaler appliance. The OR condition covers both UNIX-like shell spawning (sh, bash) and common attacker download tools (curl, wget, python). The grandparent filter suppresses legitimate package management activity.

```text
rule NetScaler_Post_Exploitation_Shell_Spawn
```

{

meta:

description = "Detects shell or download tool spawned from NetScaler daemon processes — potential post-exploitation"

author = "1898 & Co. Threat Intelligence"

date = "2026-03-25"

reference = "CVE-2026-3055, CVE-2026-4368"

hash = "N/A"

strings:

\$daemon1 = "nsaad" ascii wide nocase

\$daemon2 = "nsmgmt" ascii wide nocase

\$daemon3 = "nsvpnd" ascii wide nocase

\$daemon4 = "nsnetsvc" ascii wide nocase

\$shell1 = "/bin/sh" ascii wide

\$shell2 = "/bin/bash" ascii wide

\$tool1 = "curl" ascii wide

\$tool2 = "wget" ascii wide

\$tool3 = "python" ascii wide

```text
condition:
any of (\$daemon\*) and any of (\$shell\*, \$tool\*)
}
```
This rule targets memory artifacts from common credential dumping tools known to be used in post-NetScaler-exploitation lateral movement chains. The condition branches independently check for Mimikatz, WCE, gsecdump, and comsvcs MiniDump patterns, with a catch-all branch for memory-read API strings co-occurring with lsass. The rule requires SeDebugPrivilege-level process access to execute YARA against LSASS; use CrowdStrike RTR for remote execution. Note: This rule targets Windows LSASS tooling and will not match Linux-specific credential dumping (T1003.007). In environments with Linux runner pools or containers, include a separate Linux YARA rule (see below).

```text
rule Credential_Dump_Tool_Memory_Artifacts
```

{

meta:

description = "Detects in-memory artifacts from credential dumping tools used in post-NetScaler exploitation lateral movement"

author = "1898 & Co. Threat Intelligence"

date = "2026-03-25"

reference = "CVE-2026-3055 post-exploitation lateral movement chain"

hash = "N/A"

strings:

// Branch 1: Mimikatz

\$mimi1 = "sekurlsa::logonpasswords" ascii wide nocase

\$mimi2 = "lsadump::sam" ascii wide nocase

\$mimi3 = "privilege::debug" ascii wide nocase

\$mimi4 = "mimikatz" ascii wide nocase

\$mimi5 = { 6D 69 6D 69 6B 61 74 7A }

// Branch 2: WCE (Windows Credential Editor)

\$wce1 = "wce.exe" ascii wide nocase

\$wce2 = "lsass.exe" ascii wide nocase

// Branch 3: gsecdump

\$gsec1 = "gsecdump" ascii wide nocase

// Branch 4: comsvcs MiniDump

\$comsvc1 = "MiniDump" ascii wide

\$comsvc2 = "comsvcs" ascii wide nocase

// Catch-all: memory-read API + lsass indicator

\$memapi1 = "NtReadVirtualMemory" ascii wide

\$memapi2 = "ReadProcessMemory" ascii wide

\$lsass = "lsass.exe" ascii wide nocase

```text
condition:
any of (\$mimi\*) or
```
(\$wce1 and \$wce2) or

\$gsec1 or

(\$comsvc1 and \$comsvc2 and \$lsass) or

(any of (\$memapi\*) and \$lsass and any of (\$mimi\*, \$wce\*, \$gsec\*, \$comsvc\*))

}

This rule detects SAML AuthnRequest payloads that contain binary non-XML content or exhibit structural anomalies consistent with out-of-bounds read exploitation of CVE-2026-3055. The oversized SAML element condition (greater than 8KB for a single SAML element) and binary content co-occurrence filter are designed to reduce false positives from legitimate large SAML assertions while flagging exploit payloads. The wide modifier covers UTF-16 encoded variants.

```text
rule NetScaler_CVE_2026_3055_SAML_Exploit_Payload
```

{

meta:

description = "Detects malformed SAML request payloads consistent with CVE-2026-3055 out-of-bounds read exploitation against NetScaler SAML IDP"

author = "1898 & Co. Threat Intelligence"

date = "2026-03-25"

reference = "CVE-2026-3055 (CVSS v4.0 9.3)"

hash = "N/A"

strings:

\$saml_req = "SAMLRequest" ascii wide nocase

\$saml_auth = "AuthnRequest" ascii wide nocase

\$saml_idp = "samlIdPProfile" ascii wide nocase

// Binary content in SAML payload (non-printable bytes following SAML XML markers)

\$bin_marker = { 3C 73 61 6D 6C 70 \[0-512\] 00 00 00 00 }

// Oversized NameID or Attribute element

\$oversize = { 3C 4E 61 6D 65 49 44 \[1-8200\] 3C 2F 4E 61 6D 65 49 44 3E }

```text
condition:
```
(\$saml_req or \$saml_auth or \$saml_idp) and (\$bin_marker or \$oversize)

}

Scan command (PCAP-based, run against captured network traffic):

```text
yara -r /etc/yara/NetScaler_CVE_2026_3055_SAML_Exploit_Payload.yar /tmp/saml_inbound\_\*.pcap >> /tmp/yara_saml_exploit.txt
```

#### This rule detects exploit framework artifacts — specifically Nuclei templates and Metasploit module file structures — that may be staged on attacker-controlled hosts or found on NetScaler appliances following compromise. The OR structure independently detects the three most common exploit framework file signatures without requiring all to be present simultaneously.

```text
rule Exploit_Framework_NetScaler_CVE_2026_3055_Template
```

{

meta:

description = "Detects Nuclei, Metasploit, or custom exploit templates targeting CVE-2026-3055 or CVE-2026-4368"

author = "1898 & Co. Threat Intelligence"

date = "2026-03-25"

reference = "CVE-2026-3055, CVE-2026-4368"

hash = "N/A"

strings:

// Nuclei template markers for NetScaler SAML IDP targeting

\$nuclei1 = "CVE-2026-3055" ascii wide nocase

\$nuclei2 = "samlIdPProfile" ascii wide nocase

\$nuclei3 = "netscaler" ascii wide nocase

\$nuclei4 = "id: cve-2026-3055" ascii wide nocase

// Metasploit module structure for NetScaler exploit

\$msf1 = "Msf::Exploit::Remote" ascii wide

\$msf2 = "NetScaler" ascii wide nocase

\$msf3 = "CVE-2026-3055" ascii wide nocase

// Generic exploit script markers

\$script1 = "samlIdPProfile" ascii wide nocase

\$script2 = "out-of-bounds" ascii wide nocase

\$script3 = "memory read" ascii wide nocase

```text
condition:
```
(\$nuclei1 and \$nuclei2) or

(\$nuclei4) or

(\$msf1 and \$msf2 and \$msf3) or

(2 of (\$script\*) and \$nuclei3)

}

Scan command:

```text
yara -r /etc/yara/Exploit_Framework_NetScaler_CVE_2026_3055_Template.yar /tmp/ /var/tmp/ /root/ /home/ >> /tmp/yara_exploitframework_hits.txt
```

SIGMA Rules

```text
title: NetScaler SAML IDP Unauthenticated Memory Read Exploit Attempt
id: 4a7f8b2d-1e3c-4a5f-8b2d-1e3c4a5f8b2d
status: experimental
description: Detects HTTP POST requests to NetScaler SAML IDP endpoints with anomalous payload sizes consistent with CVE-2026-3055 exploitation
references:
- https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX696300
- https://nvd.nist.gov/vuln/detail/CVE-2026-3055
author: 1898 & Co. Threat Intelligence
date: 2026-03-25
tags:
- attack.initial_access
- attack.t1190
- cve.2026-3055
logsource:
category: webserver
product: citrix_netscaler
detection:
selection:
cs-method: POST
cs-uri-stem|contains: '/saml'
sc-bytes|gt: 65536
filter_legitimate:
c-ip|cidr:
- '10.0.0.0/8'
- '172.16.0.0/12'
- '192.168.0.0/16'
condition: selection and not filter_legitimate
falsepositives:
- Legitimate large SAML federation responses from trusted IdP partners
- Certificate-heavy SAML assertions from enterprise IdPs with large attribute sets
level: high
title: NetScaler Process Spawning Unexpected Child Process
id: 9c3e1d4b-2f5a-4c3e-1d4b-2f5a4c3e1d4b
status: experimental
description: Detects NetScaler daemon processes spawning unexpected child processes such as shells or download utilities, indicating post-exploitation command execution
references:
- https://nvd.nist.gov/vuln/detail/CVE-2026-3055
author: 1898 & Co. Threat Intelligence
date: 2026-03-25
tags:
- attack.execution
- attack.t1059.004
- cve.2026-3055
logsource:
category: process_creation
product: linux
detection:
selection_parent:
ParentImage|contains:
- 'nsaad'
- 'nsmgmt'
- 'nsvpnd'
- 'nsnetsvc'
- 'nshttpd'
selection_child:
Image|endswith:
- '/sh'
- '/bash'
- '/python'
- '/curl'
- '/wget'
- '/nc'
condition: selection_parent and selection_child
falsepositives:
- Legitimate Citrix maintenance scripts running under NetScaler daemon context
- Authorized administrative shell sessions initiated by NetScaler management tooling
level: critical
title: Credential Dump Tool Execution on Windows Host Post-NetScaler Access
id: 6b2a9f1c-3d4e-4b2a-9f1c-3d4e6b2a9f1c
status: experimental
description: Detects execution of credential dumping tools on Windows hosts accessible via NetScaler gateway, indicating lateral movement following CVE-2026-3055 exploitation
references:
- https://nvd.nist.gov/vuln/detail/CVE-2026-3055
author: 1898 & Co. Threat Intelligence
date: 2026-03-25
tags:
- attack.credential_access
- attack.t1003.001
- cve.2026-3055
logsource:
category: process_creation
product: windows
detection:
selection:
Image|endswith:
- '\mimikatz.exe'
- '\procdump.exe'
- '\procdump64.exe'
CommandLine|contains:
- 'lsass'
- 'sekurlsa'
- 'lsadump'
selection_comsvcs:
Image|endswith: '\rundll32.exe'
CommandLine|contains|all:
- 'comsvcs'
- 'MiniDump'
- 'lsass'
condition: selection or selection_comsvcs
falsepositives:
- Authorized red team exercises with prior written approval
- Legitimate forensic investigation using approved tools
level: critical
#### Snort/Suricata Rules
alert tcp any any -> $HTTP_SERVERS 443 (msg:"CVE-2026-3055 NetScaler SAML IDP Exploit Attempt - Oversized POST to SAML Endpoint"; flow:to_server,established; content:"POST"; http_method; content:"/saml"; http_uri; dsize:>8192; classtype:web-application-attack; sid:9000001; rev:1; reference:cve,2026-3055; metadata:affected_product NetScaler_ADC_Gateway, attack_target Web_Server, created_at 2026-03-25, signature_severity Major;)
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 443 (msg:"CVE-2026-3055 NetScaler SAML IDP - Scanner/Exploit Framework User-Agent"; flow:to_server,established; content:"samlIdPProfile"; nocase; pcre:"/User-Agent\s\*:\s\*(nuclei|nmap|zgrab|masscan|go-http-client|python-requests)/i"; threshold:type both, track by_src, count 5, seconds 60; classtype:attempted-recon; sid:9000002; rev:1; reference:cve,2026-3055; metadata:affected_product NetScaler_ADC_Gateway, attack_target Web_Server, created_at 2026-03-25, signature_severity Major;)
```
6. Indicators of Compromise

Network IoCs: None published in source material — monitor Citrix CTX696300 security bulletin and CISA Known Exploited Vulnerabilities catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for threat actor infrastructure IoCs as exploitation activity is confirmed and attributed.

Host IoCs: None published in source material — if exploitation is confirmed, review NetScaler nslog for anomalous SAML request sequences and perform memory forensics on the nsaad process to identify extracted data artifacts.

Behavioral IoCs:

\- HTTP POST to /saml/\* endpoint with Content-Length greater than 8192 bytes from external IP

\- HTTP response from NetScaler SAML IDP with body size greater than 65536 bytes or containing non-XML binary content

\- NetScaler daemon (nsaad, nsmgmt, nsvpnd) spawning sh, bash, curl, wget, python, or nc as child process

\- New outbound connection from NetScaler host to external IP on non-standard port within 60 seconds of SAML authentication event

\- Multiple concurrent authenticated sessions associated with the same user account from distinct external IPs (session mix-up indicator for CVE-2026-4368)

\- Windows Event ID 4648 (explicit credential logon) from IP address matching NetScaler gateway external interface

\- Rundll32.exe executing comsvcs.dll with MiniDump and lsass.exe in command line on hosts accessible via NetScaler

\- DNS query from NetScaler host to non-corporate external resolver

7. False Positive Baseline

The following known-good patterns must be baselined and suppressed to prevent alert fatigue during this hunt.

Large SAML assertions from enterprise identity providers: Some enterprise IdPs (e.g., Azure AD, Okta, Ping Identity) transmit SAML assertions containing extended attribute sets, signed assertions, and embedded certificates that may exceed 8KB. Analyst teams should baseline assertion sizes per trusted IdP and suppress size-based alerts for requests originating from known IdP IP ranges.

High-frequency automated service account logons: Monitoring tools, CI/CD pipelines, and automated application health checks may generate repetitive authentication events through NetScaler gateway. These should be documented and excluded from frequency-based anomaly thresholds by filtering on known service account identifiers.

NetScaler management and health-check processes: Citrix ADM probes, SNMP polling agents, and internal health monitoring daemons generate regular outbound connections from the NetScaler appliance. The source IP ranges for these management systems should be excluded from outbound connection anomaly queries.

Authorized penetration testing activity: If red team or external penetration testing engagements are active, their source IPs and testing windows should be documented and suppressed from SAML exploit detection signatures for the duration of the engagement, with documented exception records.

SSL session resumption from load balancer health checks: Web application firewalls and load balancers fronting NetScaler appliances perform regular SSL handshake health checks that may appear as anomalous TLS session activity. Exclude health check source IPs from TLS session resumption anomaly analysis.

Vendor-managed Citrix cloud components: Organizations using Citrix Cloud or hybrid deployments may see legitimate management traffic from Citrix cloud infrastructure IP ranges. Citrix publishes its cloud infrastructure IP ranges; these should be allowlisted in network-based detection signatures.

8. Escalation Criteria

The following conditions constitute mandatory escalation to incident response engagement:

1. Any confirmed HTTP POST to a NetScaler SAML IDP endpoint (containing "samlIdPProfile" or matched by SIGMA rule "NetScaler SAML IDP Unauthenticated Memory Read Exploit Attempt") with a response body exceeding 65,536 bytes or containing binary non-XML content, from an external IP address not in the approved IdP allowlist.

2. Any confirmed process creation event where a NetScaler daemon (nsaad, nsmgmt, nsvpnd, nsnetsvc) is the parent process of a shell interpreter (sh, bash) or network utility (curl, wget, nc) — as matched by SIGMA rule "NetScaler Process Spawning Unexpected Child Process."

3. Any YARA hit on rule NetScaler_Post_Exploitation_Shell_Spawn against any NetScaler appliance process or file system path.

4. Any YARA hit on rule Credential_Dump_Tool_Memory_Artifacts against any process running on a Windows host accessible via NetScaler gateway, particularly processes with access to the LSASS process address space.

5. Any YARA hit on rule Exploit_Framework_NetScaler_CVE_2026_3055_Template found on any internal system, indicating an attacker staging exploitation infrastructure within the network perimeter.

6. Any YARA hit on rule NetScaler_CVE_2026_3055_SAML_Exploit_Payload found in captured PCAP data from NetScaler-adjacent network interfaces.

7. Any confirmed session overlap — the same NetScaler session cookie or authentication token observed from two distinct external IP addresses within a 60-second window — consistent with CVE-2026-4368 session confusion exploitation.

8. Any outbound connection from a NetScaler appliance host to an external IP address on a port other than 80, 443, 514 (syslog), or 161/162 (SNMP) that cannot be attributed to a known management or monitoring function.

9. CISA adds CVE-2026-3055 or CVE-2026-4368 to the Known Exploited Vulnerabilities catalog — treat as presumptive exploitation attempt against any unpatched appliance and initiate emergency IR review regardless of detection status.

9. Hunt Completion Criteria and Reporting

This hunt is considered complete when all of the following conditions are met: all in-scope NetScaler appliances have been confirmed running fixed builds (14.1-66.59 or later, 13.1-62.23 or later, or 13.1-37.262 or later) through authenticated version verification; all SAML IDP and gateway/AAA virtual server configuration queries have returned results documenting configuration scope; all Collection Query data sets have been reviewed for anomalies; and all Detection Signatures have been executed against available telemetry with no unresolved hits.

The hunt completion report must contain: a confirmed inventory of all NetScaler appliances, their pre-hunt build versions, patch status, and SAML IDP / gateway configuration state; a summary of all Datadog monitor firings and CrowdStrike detection events observed during the hunt window with disposition (true positive, false positive, or inconclusive); packet capture analysis results for SAML endpoint traffic; YARA scan results for all rules defined in Section 5 across all applicable hosts and process memory targets; a final determination of whether any exploitation activity was observed, with supporting evidence; and recommendations for configuration hardening (removal of unnecessary SAML IDP configurations, access restriction to management interfaces).

Escalation Criteria §8 conditions 1–9 must each appear in the final report with a corresponding status (not triggered, triggered and closed as false positive, or triggered and escalated to IR). At minimum, one numbered condition directly tied to each YARA rule defined in Section 5 must be documented: NetScaler_Post_Exploitation_Shell_Spawn is addressed by condition 3; Credential_Dump_Tool_Memory_Artifacts by condition 4; NetScaler_CVE_2026_3055_SAML_Exploit_Payload by condition 6; Exploit_Framework_NetScaler_CVE_2026_3055_Template by condition 5.

10\. Advisory IoC Reference

| IOC Type | IOC |
|----|----|
| CVE | CVE-2026-3055 | CVSS v4.0 9.3 (Critical) | NetScaler ADC and NetScaler Gateway 14.1 before 14.1-66.59, 13.1 before 13.1-62.23, 13.1-FIPS/NDcPP before 13.1-37.262 | Unauthenticated out-of-bounds memory read via malformed SAML IDP request; no authentication or user interaction required |
| CVE | CVE-2026-4368 | CVSS v4.0 7.7 (High) | NetScaler ADC and NetScaler Gateway 14.1 before 14.1-66.59, 13.1 before 13.1-62.23, 13.1-FIPS/NDcPP before 13.1-37.262 | Race condition on gateway or AAA virtual server causing session mix-up and potential unauthorized access to another user's authenticated session |
| Threat Actor | None attributed | Opportunistic/Ransomware/Nation-State | CVEs: CVE-2026-3055, CVE-2026-4368 | Primary TTPs: T1190 (exploit public-facing application), T1021.001 (RDP lateral movement), T1003.001 (credential dumping) |
| Malware | None named in source material | N/A | No specific malware family attributed to exploitation of CVE-2026-3055 or CVE-2026-4368 at time of publication |
| Network IOC | None published in source material — monitor https://www.cisa.gov/known-exploited-vulnerabilities-catalog for threat actor infrastructure as exploitation is attributed |
| File IOC | None published in source material — review NetScaler nslog for anomalous SAML request sequences if exploitation is suspected |
| Behavioral | HTTP POST to /saml/\* with Content-Length \> 8192 bytes from non-RFC1918 source IP |
| Behavioral | NetScaler daemon (nsaad/nsmgmt/nsvpnd) spawning sh, bash, curl, wget, python, or nc as child process |
| Behavioral | Multiple concurrent authenticated sessions for same user from distinct external IPs within 60-second window (CVE-2026-4368 session confusion) |
| Behavioral | Outbound connection from NetScaler host to external IP on non-standard port (not 80/443/514/161/162) post-authentication event |
| Behavioral | Rundll32.exe executing comsvcs.dll with MiniDump and lsass.exe in command line on gateway-accessible Windows hosts |
| Behavioral | Windows Event ID 4648 (explicit credential logon) originating from NetScaler gateway IP address |
