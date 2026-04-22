# Threat Hunt Plan: BRIDGE:BREAK Serial-to-IP Converter Exploitation (CVE-2025-67039, CVE-2025-67041, CVE-2025-70082, CVE-2026-32955, CVE-2026-32956, CVE-2026-32958, CVE-2026-32960, CVE-2026-32965)

> Date: 2026-04-22 | Revision: 1.0

# Hunt Objective and Scope

The objective of this hunt is to identify evidence of exploitation, pre-exploitation reconnaissance, or post-exploitation pivot activity targeting Lantronix EDS3000PS (firmware ≤ 3.1.0.0R2), Lantronix EDS5000 (firmware ≤ 2.1.0.0R3), and Silex SD-330AC (firmware ≤ 1.42) serial-to-IP converters and the companion Silex AMC Manager (version ≤ 5.0.2). The hunt assumes that affected devices are reachable to some subset of adversaries either directly from the internet, from a partner network, or after initial access has already been obtained via a compromised internet-facing edge appliance.

#### Environmental scope covers: OT network segments hosting these converters, healthcare biomedical VLANs where Silex SD-330AC is used as a wireless bridge, administrative jump hosts used to manage the converters, SPAN/TAP feeds on the OT-edge aggregation layer, firewall and NGFW management-plane logs, NetFlow collectors, and any cloud-forwarded audit or web-access logs that observe management traffic toward these devices. Because the converters themselves do not host conventional EDS agents, hunt queries against CrowdStrike Falcon and Datadog Live Process Monitoring are framed around adjacent Windows and Linux hosts — engineering workstations, historian and SCADA servers, jump boxes, and CVD/monitoring appliances — that interact with the converters on the management plane.

Time window: the default hunt horizon is the prior 30 days from execution, extended to 90 days in environments where Forescout has identified a public-internet-exposed converter. Escalate to a full incident-response investigation if any exploitation indicator fires.

# Hypotheses and Hunt Procedures

## Hypothesis 1

A remote unauthenticated attacker has exploited CVE-2025-67041 or CVE-2025-70082 against a Lantronix EDS3000PS Filesystem Browser TFTP client or the ltrx_evo component, observable as anomalous outbound TFTP traffic, unexpected command-injection payloads in web management POST bodies, and new connections originating from the converter management IP toward internet or OT-internal hosts on non-standard ports.

### MITRE ATT&CK

Initial Access | T1190 — Exploit Public-Facing Application | Direct exploitation of the converter web management interface to gain execution on the device.

### MITRE ATT&CK

Execution | T1059.004 — Command and Scripting Interpreter: Unix Shell | Injected OS commands execute with root privilege through the TFTP host-parameter sink.

### Collection Queries

CrowdStrike Falcon FQL — inventory monitoring/jump hosts that communicate with converter IPs so downstream joins have process context:

```text
#event_simpleName = "NetworkConnectIP4"
| RemotePort = "80" OR RemotePort = "443" OR RemotePort = "30718" OR RemotePort = "9999"
| cidr(RemoteAddressIP4, subnet=["<converter_subnet_1>", "<converter_subnet_2>"])
| join(query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)}, field=[aid,RawProcessId], include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName])
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName])
```

CrowdStrike Falcon FQL — detect web-client processes on admin hosts that submitted requests with exploit path markers for the Filesystem Browser TFTP client:

```text
#event_simpleName = "ProcessRollup2"
| FileName = /^(curl\\exe|wget\\exe|python\\exe|python3\\exe|powershell\\exe|pwsh\\exe)$/i
| CommandLine = /filesystem|tftp|host=|FsBrowser/i
| table([ComputerName, AuthenticationId, UserName, ImageFileName, FileName, CommandLine, ParentBaseFileName])
```

BPF packet capture on the OT-edge SPAN feed — isolate converter management plane and TFTP traffic into a rolling 24-hour capture set:

```text
tcpdump -i <span_iface> -G 3600 -W 24 -C 500 -w /var/pcap/bridgebreak-mgmt-%Y%m%d%H.pcap '(host <converter_ip_list>) and (tcp port 80 or tcp port 443 or tcp port 9999 or tcp port 30718 or udp port 69)'
```

BPF packet capture — opportunistic IoT probes on ports 30718 (Lantronix Discovery Protocol) and 9999 (Lantronix Telnet/Setup port):

```text
tcpdump -i <span_iface> -G 3600 -W 72 -w /var/pcap/bridgebreak-disc-%Y%m%d%H.pcap 'udp port 30718 or tcp port 9999'
```

Datadog Log Search — fallback visibility where Live Process Monitoring is not enabled; correlates web-access logs forwarded from NGFW/WAF to Datadog:

```text
source:windows (message:"filesystem" OR message:"FsBrowser" OR message:"tftp") @network.client.ip:(<converter_subnet_1> OR <converter_subnet_2>)
// time range: now - 30d to now — Analytics Table view; group by @network.client.ip, @usr.name
```

Datadog Log Search — capture HTTP traffic where the NGFW is forwarding syslog to Datadog:

```text
source:paloalto @evt.name:THREAT (@url.path:\*FsBrowser\* OR @url.path:\*filesystem\* OR @payload:\*host=\*\\\*)
// time range: now - 30d to now
```

Datadog Live Process Monitoring (Infrastructure \> Processes) — curl/wget/python invocations on admin hosts with exploit URL fragments:

```text
command:curl user:\* OR command:wget user:\* OR command:python user:\*
// Free-text filter: filesystem OR FsBrowser OR tftp-host
```

Datadog source:cloudtrail — surface any unexpected AWS API activity originating from network paths that traverse the converter management VLAN (rare but catches VPC flow log anomalies when converters are cloud-tethered):

```text
source:cloudtrail @evt.name:(AssumeRole OR GetSessionToken) -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*
// time range: now - 30d to now
```

Windows Event IDs to collect on admin/jump hosts — forward via WEF or use Get-WinEvent:

\- 4688 (Process Creation) — capture curl/python launches

\- 4624 (Logon Success) — new logons to admin hosts around exploit window

\- 4104 (PowerShell ScriptBlock) — PowerShell sessions touching converter IPs

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $\_.Message -match 'curl|wget|python|Invoke-WebRequest' -and $\_.Message -match '(filesystem|tftp|FsBrowser)' } | Export-Csv -Path C:\hunt\bb-admin-webclients.csv -NoTypeInformation
```

OT Data Collection: Claroty CTD — Administration \> Reports \> Connection Activity; filter Protocol = HTTP, HTTPS, TFTP; Source or Destination IP = converter IP list; date range = 30 days; export CSV to C:\hunt\ctd-bb-conns.csv

OT Data Collection: Dragos Platform — Investigate \> Connection Timeline; filter Protocol = HTTP, HTTPS, TFTP and Destination IP in converter list; Detections panel filtered by Category = Initial Access or Execution for alert-driven collection

OT Data Collection: Nozomi Networks — Assets \> Connections; filter Protocol = HTTP/HTTPS/TFTP and Endpoint = converter IP; export via GET /api/open/connections?protocol=tftp&host=\<converter_ip\>

OT Data Collection: Armis — Asset Management \> Devices \> filter Manufacturer = Lantronix OR Silex; export CSV; inspect Policy engine alerts for policy violations referencing these devices over the hunt window

OT Data Collection: Tenable OT — Assets \> Devices \> Export; Reports \> Network Map; REST API: GET /api/v1/assets and GET /api/v1/events to pull connection and event lists filtered by converter asset IDs; check Vulnerabilities view for BRIDGE:BREAK CVE hits across the asset inventory

OT Data Collection: Forescout eyeInspect — Inventory \> Devices \> Export; Web API GET /api/v1/assets and GET /api/v1/connections; check the Threat Detection panel for anomalous HTTP/TFTP session alerts on converter endpoints

SNMP polling — rolling device-side and switch-port counter collection during hunt window:

```text
snmpwalk -v2c -c <community> <switch_ip> IF-MIB::ifTable
snmpget -v2c -c <community> <switch_ip> IF-MIB::ifInOctets.<ifIndex> IF-MIB::ifOutOctets.<ifIndex> IF-MIB::ifInErrors.<ifIndex> IF-MIB::ifOutErrors.<ifIndex>
snmpwalk -v2c -c <community> <converter_ip> system
snmpwalk -v2c -c <community> <converter_ip> IF-MIB::ifTable
# SNMPv3 variant where configured:
snmpwalk -v3 -l authPriv -u <user> -a SHA -A <authpass> -x AES -X <privpass> <converter_ip> system
YARA file-system scan — stage on admin jump hosts and forensic shares for dropped exploit tooling or captured PCAPs containing exploit strings:
yara -r /opt/yara/rules/bridgebreak.yar C:\users\\ C:\ProgramData\\ C:\hunt\\ >> C:\hunt\yara-bb-disk.txt
```

### Analysis Queries

CrowdStrike Falcon FQL — rate anomaly on admin-host web-client connections to converter IPs (unusual volume suggests automation/exploitation):

```text
#event_simpleName = "NetworkConnectIP4"
| cidr(RemoteAddressIP4, subnet=["<converter_subnet_1>", "<converter_subnet_2>"])
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=count(), limit=100000)
| sort(\_count, order=desc, limit=50)
```

CrowdStrike Falcon FQL — rarity hunt for admin hosts that have never historically touched converter IPs:

```text
#event_simpleName = "NetworkConnectIP4"
| cidr(RemoteAddressIP4, subnet=["<converter_subnet_1>", "<converter_subnet_2>"])
| groupBy([ComputerName, FileName], function=count(), limit=100000)
| sort(\_count, order=asc, limit=50)
```

Wireshark display filter — review captured PCAP for exploit markers in HTTP traffic:

http.request.uri contains "FsBrowser" or http.request.uri contains "filesystem" or http.request.uri matches "host=\[^&\]\*\[;|\`\]"

```text
tshark -r bridgebreak-mgmt-\*.pcap -Y 'http.request.uri contains "FsBrowser" or http.request.uri matches "host=[^&]\*[;|\`]"' -T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri >> tshark-bb-uri.txt
```

Wireshark display filter — outbound TFTP from converter IPs reaching non-approved hosts (exfil/tool staging path):

udp.port == 69 and ip.src == \<converter_ip\>

```text
tshark -r bridgebreak-mgmt-\*.pcap -Y 'udp.port == 69 and ip.src in {<converter_ip_list>}' -T fields -e frame.time -e ip.src -e ip.dst -e udp.dstport >> tshark-bb-tftp.txt
```

Datadog Log Analytics — rate spikes in URL path hits matching exploit markers:

```text
source:paloalto (@url.path:\*FsBrowser\* OR @url.path:\*filesystem\*) @dest.ip:(<converter_subnet_1> OR <converter_subnet_2>)
// Use Timeseries view; group by @url.path; time range last 30 days — investigate any bucket with > 5x median count
```

Datadog Audit Trail — surface admin-account changes coincident with exploit windows:

```text
source:datadog @evt.category:user_access @evt.name:login
// time range: now - 30d to now; group by @usr.name
```

Datadog Monitor (required):

```text
Type: Log Alert
Query: source:paloalto @url.path:\*FsBrowser\* OR source:paloalto @payload:\*host=\*\\\*
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: BRIDGE:BREAK CVE-2025-67041 exploit pattern observed against Lantronix EDS3000PS — immediate investigation required @pagerduty-soc"
```

Prerequisites: Palo Alto NGFW syslog forwarding to Datadog with URL filtering inspection enabled

Create via: Monitors \> New Monitor \> Log Alert

Windows Event Log PowerShell analysis — correlate 4688 process creations on admin hosts with converter-directed connections:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $\_.Message -match '(curl|wget|python|Invoke-WebRequest|Invoke-RestMethod)' } | Select-Object TimeCreated,@{N='CmdLine';E={$\_.Properties[8].Value}},@{N='Account';E={$\_.Properties[1].Value}} | Export-Csv -Path C:\hunt\bb-h1-proc.csv -NoTypeInformation
```

OT Protocol Analysis — after the converter, inspect the serial side via captured data if the platform offers; check Claroty/Dragos/Nozomi for CIP, Modbus, or raw-TCP anomalies originating from converter IP within 5 minutes of any suspected exploitation event

```text
YARA memory scan — scan curl/wget/python processes on admin hosts for in-memory exploit URL fragments or reverse-shell staging:
```

PowerShell: Get-Process curl,wget,python,pwsh -ErrorAction SilentlyContinue | ForEach-Object { yara -p $_.Id C:\hunt\rules\bridgebreak.yar \>\> C:\hunt\yara-bb-mem.txt }

Remote at scale via CrowdStrike RTR: execute a custom script that invokes YARA -p across candidate PIDs; results returned to RTR session

## Hypothesis 2

An attacker has bypassed authentication on a Lantronix EDS3000PS (CVE-2025-67039) or a Silex SD-330AC (CVE-2026-32960) using the alternate-path URL suffix with an Authorization header containing admin, or via crafted login packet reusing retained credentials, observable as HTTP 200 responses to management paths with unusual URL suffixes and Authorization header patterns in web/WAF logs and firewall application logs.

### MITRE ATT&CK

Defense Evasion | T1078 — Valid Accounts | Reuse of retained admin credentials via the Silex flaw impersonates a legitimate user.

### MITRE ATT&CK

Initial Access | T1190 — Exploit Public-Facing Application | The Lantronix alternate-path flaw permits authenticated-equivalent access without credentials.

### Collection Queries

Datadog Log Search — capture NGFW/WAF HTTP logs for Authorization headers and unusual URL suffix patterns directed at converter management IPs:

```text
source:paloalto (@url.path:\*setup\* OR @url.path:\*admin\* OR @url.path:\*system\*) @http.auth_user:admin @dest.ip:(<converter_subnet_1> OR <converter_subnet_2>)
// time range: now - 30d to now; Analytics Table view; group by @network.client.ip
```

Datadog Log Search — alternate: surface any management-path hit from a non-baseline source IP:

```text
source:paloalto @dest.ip:(<converter_subnet_1> OR <converter_subnet_2>) @url.path:\*
// time range: now - 30d to now; Analytics Top List view; group by @network.client.ip
```

Datadog Live Process Monitoring — admin-host processes generating crafted HTTP requests with Authorization: admin:

```text
command:curl user:\* OR command:python user:\*
// Free-text filter: Authorization OR admin\\\\ OR auth=admin
```

BPF capture — capture HTTP Authorization headers on converter management plane:

```text
tcpdump -i <span_iface> -G 3600 -W 48 -C 500 -w /var/pcap/bb-authhdr-%Y%m%d%H.pcap 'tcp and (tcp port 80 or tcp port 443 or tcp port 9999) and (host <converter_ip_list>)'
```

Windows Event IDs to collect — 4104 (PowerShell ScriptBlock) for Authorization-header manipulation, 4688 for curl/Invoke-WebRequest:

```text
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $\_.Message -match '(Authorization|Basic\s+YWRt|admin:)' } | Export-Csv -Path C:\hunt\bb-h2-ps.csv -NoTypeInformation
```

CrowdStrike Falcon FQL — hunt admin-host processes that embed Basic-admin Authorization:

```text
#event_simpleName = "ProcessRollup2"
| CommandLine = /Authorization.\*(Basic\s+YWRt|admin:)/i
| table([ComputerName, AuthenticationId, UserName, FileName, CommandLine, ParentBaseFileName])
```

OT Data Collection: Claroty CTD — Administration \> Reports \> Connection Activity; Protocol = HTTP/HTTPS; inspect packet-level for Authorization header anomalies

OT Data Collection: Dragos Platform — Investigate \> Connection Timeline; flag HTTP sessions targeting converter IPs from source IPs not in approved admin list

OT Data Collection: Nozomi Networks — Assets \> Connections; filter Protocol = HTTP; export via GET /api/open/connections?protocol=http

OT Data Collection: Armis — Policy engine: add a policy for "HTTP to Lantronix/Silex converter from non-admin-subnet source" and review violations

OT Data Collection: Tenable OT — Events view; filter Event Type = Unauthorized Access and destination asset = converter inventory IDs

OT Data Collection: Forescout eyeInspect — Threat Detection panel; inspect HTTP anomaly alerts on converter endpoints

```text
YARA file-system scan — scan for stored exploit scripts or captured requests with auth-bypass patterns:
yara -r /opt/yara/rules/bridgebreak.yar /var/pcap/ C:\hunt\\ >> /var/log/yara-bb-authbypass.txt
```

### Analysis Queries

Datadog Log Analytics — rate anomalies and unauthorized-source analysis:

```text
source:paloalto @dest.ip:(<converter_subnet_1> OR <converter_subnet_2>) @status:200 @http.auth_user:admin
// Use Timeseries view; group by @network.client.ip; time range last 30 days; investigate any source IP outside the admin allowlist
```
Datadog Audit Trail — correlate with any Datadog admin account changes in the same window:

```text
source:datadog @evt.category:user_management @evt.name:(role_change OR user_created)
// time range: now - 30d to now
```

Datadog Monitor (required):

```text
Type: Log Alert
Query: source:paloalto @dest.ip:(<converter_subnet_1> OR <converter_subnet_2>) @status:200 @http.auth_user:admin -@network.client.ip:<admin_subnet>
Evaluation window: last 10 minutes
Alert condition: count > 0
Message: "ALERT: Unauthenticated-admin access pattern on BRIDGE:BREAK converter — verify source IP against admin allowlist @pagerduty-soc"
Prerequisites: NGFW logs with URL filtering and Authorization header visibility forwarded to Datadog
```
Wireshark display filter — inspect Authorization header patterns reaching converter IPs:

http.authorization contains "admin:" or http.request.uri matches "(setup|admin|system)\[^/\]\*\$"

```text
tshark -r bb-authhdr-\*.pcap -Y 'http.authorization' -T fields -e frame.time -e ip.src -e ip.dst -e http.authorization -e http.request.uri >> tshark-bb-auth.txt
```

Windows Event Log PowerShell analysis — correlate admin-host logons within 5 minutes of suspected auth-bypass events:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $\_.Properties[8].Value -eq 3 } | Export-Csv -Path C:\hunt\bb-h2-logon.csv -NoTypeInformation
YARA memory scan — detect in-memory exploit request strings in running curl/python/wget processes:
Get-Process curl,wget,python,pwsh -ErrorAction SilentlyContinue | ForEach-Object { yara -p $\_.Id C:\hunt\rules\bridgebreak.yar >> C:\hunt\yara-bb-mem-h2.txt }
```

## Hypothesis 3

An attacker has leveraged the Silex SD-330AC hard-coded firmware signing key (CVE-2026-32958) or the firmware-update tampering primitive to apply a modified firmware image to a Silex converter, observable as unexpected firmware-update syslog events, altered device fingerprints in asset management platforms, and SNMP sysUpTime resets inconsistent with scheduled maintenance windows.

### MITRE ATT&CK

Persistence | T1542.005 — Pre-OS Boot: TFTP Boot and similar | Malicious firmware replaces vendor firmware to establish persistent implants below the OS.

### MITRE ATT&CK

Impair Defenses | T1554 — Compromise Client Software Binary | Firmware tampering enables long-term stealth and integrity compromise.

### Collection Queries

SNMP polling — rolling sysUpTime/sysDescr collection every 5 minutes for all converter assets:

while true; do for ip in \<converter_ip_list\>; do snmpwalk -v2c -c \<community\> \$ip system | tee -a /var/log/snmp-bb-\$(date +%F).log; done; sleep 300; done

Datadog Log Search — firmware-update and reboot indications from forwarded syslog:

```text
source:syslog (message:"firmware" OR message:"reboot" OR message:"coldStart" OR message:"warmStart") @host.ip:(<converter_ip_list>)
// time range: now - 90d to now; Analytics Table view; group by @host.ip
```

BPF capture — firmware-image HTTP(S) transfers to Silex converters:

```text
tcpdump -i <span_iface> -G 3600 -W 48 -C 500 -w /var/pcap/bb-fwload-%Y%m%d%H.pcap 'host <silex_ip_list> and (tcp port 80 or tcp port 443 or tcp port 9999)'
```

OT Data Collection: Claroty CTD — Baselines \> Asset Fingerprints; flag any Silex SD-330AC that shows new firmware version outside the planned deployment window

OT Data Collection: Dragos Platform — Detections panel filtered by Category = Firmware Change; review associated connection timeline

OT Data Collection: Nozomi Networks — Assets \> Devices \> inspect Firmware Version column and deltas; GET /api/open/assets for programmatic diff

OT Data Collection: Armis — Device Timeline per Silex asset; inspect firmware change events

OT Data Collection: Tenable OT — Events view; Event Type = Firmware Change Detected; correlate with IP and timestamp

OT Data Collection: Forescout eyeInspect — Inventory diff report comparing asset fingerprints across consecutive weekly snapshots

```text
YARA file-system scan — scan forensic image or staged firmware directory for tampered firmware signatures (absence of vendor signing-key match, presence of known bad strings):
yara -r /opt/yara/rules/bridgebreak_fw.yar /mnt/forensic/ /var/firmware-staging/ >> /var/log/yara-bb-fw.txt
```

Windows Event IDs to collect — on admin host that might have initiated the firmware update:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $\_.Message -match '(AMCManager|silex|firmware|\\bin|\\img)' } | Export-Csv -Path C:\hunt\bb-h3-fwadmin.csv -NoTypeInformation
```

CrowdStrike Falcon FQL — monitoring/jump hosts that wrote a firmware image to disk:

```text
#event_simpleName = "NewExecutableWritten"
| TargetFileName = /silex|sd-?330|firmware.\*\\(bin|img|rom)$/i
| table([ComputerName, TargetFileName, FilePath, ContextProcessId])
```

### Analysis Queries

Datadog Log Analytics — firmware-event baseline deviation:

```text
source:syslog (message:"firmware" OR message:"Firmware uploaded" OR message:"warmStart") @host.ip:(<silex_ip_list>)
// Use Timeseries view; group by @host.ip; time range last 90 days; any non-maintenance-window bucket is suspect
```

Datadog Monitor (required):

```text
Type: Log Alert
Query: source:syslog (message:"firmware" OR message:"warmStart" OR message:"coldStart") @host.ip:(<silex_ip_list>)
Evaluation window: last 15 minutes
Alert condition: count > 0 outside maintenance window
Message: "ALERT: Firmware/reboot event on Silex SD-330AC outside change window — potential BRIDGE:BREAK firmware tampering @pagerduty-soc"
```

Prerequisites: Syslog from Silex converters and/or OT monitoring platform forwarded to Datadog; maintenance-window schedule documented in monitor tags

Wireshark display filter — firmware POST to SD-330AC web interface:

http.request.method == "POST" and (http.request.uri contains "firmware" or http.request.uri contains "upload") and ip.dst in {\<silex_ip_list\>}

```text
tshark -r bb-fwload-\*.pcap -Y 'http.request.method == "POST" and http.request.uri contains "firmware"' -T fields -e frame.time -e ip.src -e ip.dst -e http.content_length >> tshark-bb-fwpost.txt
```

OT Protocol Analysis — compare current device hashes to known-good vendor firmware hashes via OT platform APIs (Claroty, Nozomi, Forescout); any mismatch is automatic escalation

```text
YARA memory scan — on any Windows admin host suspected to have pushed firmware; scan active sessions and transfer processes:
Get-Process | Where-Object { $\_.ProcessName -match 'AMCManager|curl|wget|python' } | ForEach-Object { yara -p $\_.Id C:\hunt\rules\bridgebreak_fw.yar >> C:\hunt\yara-bb-fw-mem.txt }
```

## Hypothesis 4

An attacker with control of a compromised serial-to-IP converter has pivoted onto the OT or healthcare network, observable as unusual east-west traffic originating from the converter management IP toward PLCs, medical instruments, historians, or engineering workstations, and as anomalous serial command sequences on the downstream serial side that diverge from historian baselines.

### MITRE ATT&CK

Lateral Movement | T1210 — Exploitation of Remote Services | Use of the compromised converter as a pivot to reach downstream OT/medical endpoints.

### MITRE ATT&CK

Impact | T0831 — Manipulation of Control (ICS) | Injection or alteration of serial commands reaching PLCs or instruments with operational consequence.

### Collection Queries

BPF capture — east-west from converter IP to OT/medical device VLANs:

```text
tcpdump -i <ot_span_iface> -G 3600 -W 48 -C 500 -w /var/pcap/bb-eastwest-%Y%m%d%H.pcap 'src host <converter_ip> and not (dst host <management_jump_host_list>)'
```

Datadog Log Search — flow records showing converter-originated east-west traffic:

```text
source:netflow @network.source.ip:(<converter_subnet_1> OR <converter_subnet_2>) -@network.destination.ip:(<admin_jump_subnet>)
// time range: now - 30d to now; Analytics Table view; group by @network.destination.ip, @network.destination.port
```

Datadog Live Process Monitoring — any admin-host session with Modbus/CIP/OPC-UA client tooling initiated around converter pivot windows:

```text
command:modbus-cli user:\* OR command:opcua user:\* OR command:ethernetip user:\*
```

CrowdStrike Falcon FQL — engineering workstations that received connections from the converter IP (reverse hunt):

```text
#event_simpleName = "NetworkReceiveAcceptIP4"
| cidr(RemoteAddressIP4, subnet=["<converter_subnet_1>", "<converter_subnet_2>"])
| join(query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)}, field=[aid,RawProcessId], include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName])
| table([ComputerName, FileName, RemoteAddressIP4, LocalPort, CommandLine, ParentBaseFileName])
```

OT Data Collection: Claroty CTD — Baselines \> Communication Patterns; flag any new connection pair involving converter IPs

OT Data Collection: Dragos Platform — Detections panel filtered by Category = Lateral Movement or Discovery with source IP = converter

OT Data Collection: Nozomi Networks — Assets \> Connections; GET /api/open/connections?source_ip=\<converter_ip\>; diff against 30-day baseline

OT Data Collection: Armis — Policy engine: pre-create a policy "New east-west flow from Lantronix/Silex converter" and review violations

OT Data Collection: Tenable OT — Network Map; identify new edges originating from converter assets in the prior 30 days

OT Data Collection: Forescout eyeInspect — Connections view; filter Source = converter asset; export deltas from baseline

Historian / SCADA alarm correlation — pull OSI PI, GE Proficy, or AVEVA System Platform audit trails for operator-initiated commands and sensor-value edits occurring within five minutes of any converter east-west event

Windows Event IDs to collect — on engineering workstations and historian/SCADA servers:

```text
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-30)} | Where-Object { $\_.Message -match '<converter_ip_pattern>' } | Export-Csv -Path C:\hunt\bb-h4-wfp.csv -NoTypeInformation
```

SNMP polling — hunt for interface error/utilization spikes on switch ports facing OT/medical endpoints that sit downstream of the converter:

```text
snmpwalk -v2c -c <community> <ot_switch_ip> IF-MIB::ifTable
snmpget -v2c -c <community> <ot_switch_ip> IF-MIB::ifInOctets.<plc_port> IF-MIB::ifInErrors.<plc_port>
```

### Analysis Queries

Wireshark display filter — EtherNet/IP CIP service code analysis from converter:

cip and ip.src == \<converter_ip\>

```text
tshark -r bb-eastwest-\*.pcap -Y 'cip and ip.src == <converter_ip>' -T fields -e frame.time -e ip.src -e ip.dst -e cip.service >> tshark-bb-cip.txt
```

Wireshark display filter — Modbus function-code review:

modbus and ip.src == \<converter_ip\>

```text
tshark -r bb-eastwest-\*.pcap -Y 'modbus and ip.src == <converter_ip>' -T fields -e frame.time -e mbtcp.trans_id -e modbus.func_code >> tshark-bb-modbus.txt
```

Datadog Log Analytics — flow deltas:

```text
source:netflow @network.source.ip:(<converter_subnet_1> OR <converter_subnet_2>)
// Use Top List view; group by @network.destination.ip; compare against previous 30-day period; any new destination is suspect
```

Datadog Monitor (required):

```text
Type: Log Alert
Query: source:netflow @network.source.ip:(<converter_subnet_1> OR <converter_subnet_2>) -@network.destination.ip:(<baseline_destination_subnet>)
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: New east-west flow from BRIDGE:BREAK converter — validate against baseline @pagerduty-soc"
```

Prerequisites: NetFlow/VPC flow logs from OT-edge switches forwarded to Datadog; baseline destination subnet tag maintained

CrowdStrike Falcon FQL — unexpected process on engineering workstation coincident with converter-originated connection:

```text
#event_simpleName = "ProcessRollup2"
| FileName = /^(rslogix5000\\exe|studio5000\\exe|logixdesigner\\exe|opc.\*\\exe)$/i
| table([ComputerName, AuthenticationId, UserName, ImageFileName, FileName, CommandLine, ParentBaseFileName])
```

Historian baseline deviation — pull tag-level statistics (mean, stddev) for critical setpoints over the 30-day prior period; flag any reading more than 3 sigma from baseline coinciding with a converter-east-west event

OT Protocol Analysis — Claroty/Dragos/Nozomi baseline-deviation reports: any new CIP service code, Modbus function code, or OPC-UA method invocation originating from converter IP in the prior 30 days

```text
YARA memory scan — on engineering workstations and historian servers that received connections from the converter:
Get-Process | Where-Object { $\_.ProcessName -match 'rslogix|studio5000|opc|historian|pi.\*' } | ForEach-Object { yara -p $\_.Id C:\hunt\rules\bridgebreak.yar >> C:\hunt\yara-bb-h4-mem.txt }
```

# Threat Actor Profile

Opportunistic mass-scanning actors are the highest-probability first exploiters. Tools such as ZGrab, Nuclei templates, and custom Python scripts will be updated to fingerprint Lantronix EDS3000PS and Silex SD-330AC banners and to attempt the pre-authentication command injection and heap overflow chains within days of proof-of-concept release; attribution is likely to remain unclear and activity will present as generic botnet or crypto-mining enrollment.

Nation-state OT-focused actors (Volt Typhoon, Sandworm, Lazarus DPRK sub-clusters, Iranian OilRig and APT33 contractors) have historically targeted edge appliances as staging positions into critical-infrastructure OT networks. Their tradecraft against BRIDGE:BREAK-class devices would be characterized by low-and-slow reconnaissance, use of valid-appearing Authorization headers to blend with admin traffic, selective firmware tampering rather than noisy payloads, and longer dwell time focused on serial-side command manipulation rather than immediate disruption.

Ransomware affiliates and initial-access brokers are the middle tier. They will weaponize the pre-authentication RCE flaws for initial foothold into industrial networks whose IT/OT boundary protections have degraded, then sell access to ransomware operators or OT-targeting actors. Insider abuse is lower-probability but credible where serial-to-IP converters are under the administrative control of OEM or integrator staff with over-broad remote access.

# Data Sources Required

***Network:*** firewall and NGFW logs (Palo Alto, Fortinet, Check Point), NGFW URL-filtering records, NetFlow/sFlow from OT-edge aggregation, SPAN/TAP feeds into standalone IDS/IDPS (Snort, Suricata, Zeek), packet captures from rolling tcpdump, VPN gateway logs.

***Endpoint:*** CrowdStrike Falcon from engineering workstations, historian/SCADA servers, admin jump hosts, AMC Manager servers; Windows Event Logs (Security, System, PowerShell/Operational, WFP); Sysmon from high-value admin hosts; Datadog Agent with Live Process Monitoring on Linux administrative and monitoring appliances.

***OT/ICS:*** historian alarm and audit logs (OSI PI, AVEVA System Platform, GE Proficy), SCADA console logs, PLC logs where supported, OT monitoring platform exports from Claroty CTD, Dragos Platform, Nozomi Networks, Armis, Tenable OT, and Forescout eyeInspect.

***Vendor/device:*** Silex SD-330AC and AMC Manager syslog forwarding, Lantronix EDS3000PS/EDS5000 syslog (where configured), SNMP polling results from the converters themselves and from the switches carrying their traffic, SNMP trap receiver logs for coldStart/warmStart/linkDown/linkUp events.

# Detection Signatures

#### SIGMA Rule 1 — NGFW/proxy category: Authentication-bypass URL pattern for Lantronix EDS3000PS CVE-2025-67039

```text
title: BRIDGE:BREAK Lantronix EDS3000PS Authentication Bypass Pattern
id: 7a1e3b21-6f2c-4f9a-9c7a-2b8d0c1e4f61
status: experimental
description: Detects HTTP requests to Lantronix EDS3000PS management pages that include the alternate-path URL suffix and an Authorization header containing admin as the user, consistent with CVE-2025-67039.
references:
- https://nvd.nist.gov/vuln/detail/CVE-2025-67039
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-02
author: 1898 & Co. Threat Hunt
date: 2026-04-22
tags:
- attack.initial_access
- attack.t1190
- cve.2025.67039
logsource:
category: proxy
product: paloalto
detection:
selection_dest:
dst_ip|contains:
- '\<converter_subnet_1\>'
- '\<converter_subnet_2\>'
selection_hdr:
cs-uri-stem|re: '(setup|admin|system)\[^/\]\*\$'
http-auth-user: 'admin'
condition: selection_dest and selection_hdr
falsepositives:
- Legitimate administrative browser sessions on admin jump hosts within the allowlisted admin subnet
level: high
#### SIGMA Rule 2 — network_connection category: Outbound TFTP from converter IP ranges
title: BRIDGE:BREAK Converter Outbound TFTP (CVE-2025-67041 Exploit Post-Condition)
id: 1c2d3e4f-5a6b-47c8-9d0e-1f2a3b4c5d6e
status: experimental
description: Detects outbound TFTP connections from serial-to-IP converter IP ranges, an expected artifact of the CVE-2025-67041 TFTP client command-injection exploit.
references:
- https://nvd.nist.gov/vuln/detail/CVE-2025-67041
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-02
author: 1898 & Co. Threat Hunt
date: 2026-04-22
tags:
- attack.execution
- attack.t1059.004
- cve.2025.67041
logsource:
category: network_connection
product: zeek
detection:
selection:
src_ip|contains:
- '\<converter_subnet_1\>'
- '\<converter_subnet_2\>'
dst_port: 69
condition: selection
falsepositives:
- Legitimate TFTP file transfer during documented firmware distribution windows
level: high
#### SIGMA Rule 3 — process_creation category on admin hosts: curl/python invocation with BRIDGE:BREAK exploit markers
title: BRIDGE:BREAK Admin Host Exploit Client Invocation
id: 2b3c4d5e-6f7a-48b9-ac1d-2e3f4a5b6c7d
status: experimental
description: Detects curl, wget, python, or PowerShell Invoke-WebRequest invocations on admin or engineering hosts whose command line matches known BRIDGE:BREAK exploit URL fragments or Authorization header patterns.
references:
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-02
- https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10
author: 1898 & Co. Threat Hunt
date: 2026-04-22
tags:
- attack.initial_access
- attack.t1190
- attack.execution
- attack.t1059
logsource:
category: process_creation
product: windows
detection:
selection_img:
Image|endswith:
- '\curl.exe'
- '\wget.exe'
- '\python.exe'
- '\python3.exe'
- '\powershell.exe'
- '\pwsh.exe'
selection_cmd:
CommandLine|re: '(filesystem|FsBrowser|ltrx_evo|host=\[^& \]\*\[;|\`\]|Authorization.\*Basic\s+YWRt)'
condition: selection_img and selection_cmd
falsepositives:
- Red-team or penetration-test engagements targeting converter devices with documented scope
level: high
#### Snort/Suricata Rule 1 — HTTP URI pattern for Lantronix EDS3000PS TFTP host-parameter command injection (CVE-2025-67041)
alert http any any -> <converter_ip_list> any (msg:"BRIDGE:BREAK Lantronix EDS3000PS TFTP Host Parameter Command Injection Attempt"; flow:to_server,established; http.uri; content:"FsBrowser"; nocase; http.uri; pcre:"/host=[^&]\*[;|\`\\\]/i"; threshold: type limit, track by_src, count 1, seconds 60; classtype:web-application-attack; reference:cve,2025-67041; reference:url,nvd.nist.gov/vuln/detail/CVE-2025-67041; sid:100026001; rev:1; metadata:campaign BridgeBreak, product Lantronix EDS3000PS;)
#### Snort/Suricata Rule 2 — HTTP Authorization header pattern for Lantronix EDS3000PS auth bypass (CVE-2025-67039)
alert http any any -> <converter_ip_list> any (msg:"BRIDGE:BREAK Lantronix EDS3000PS Authentication Bypass Pattern"; flow:to_server,established; http.uri; pcre:"/(setup|admin|system)[^/]\*$/i"; http.header; content:"Authorization: Basic YWRt"; nocase; threshold: type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:cve,2025-67039; reference:url,nvd.nist.gov/vuln/detail/CVE-2025-67039; sid:100026002; rev:1; metadata:campaign BridgeBreak, product Lantronix EDS3000PS;)
#### Snort/Suricata Rule 3 — HTTP POST pattern for Silex SD-330AC heap overflow via redirect URL (CVE-2026-32956)
alert http any any -> <silex_ip_list> any (msg:"BRIDGE:BREAK Silex SD-330AC Redirect URL Overflow Attempt"; flow:to_server,established; http.uri; content:"login"; nocase; http.request_body; pcre:"/redirect[=]?[^&]{200,}/i"; threshold: type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:cve,2026-32956; reference:url,nvd.nist.gov/vuln/detail/CVE-2026-32956; sid:100026003; rev:1; metadata:campaign BridgeBreak, product Silex SD-330AC;)
```
#### YARA Rule 1 (disk artifacts) — BridgeBreak_Exploit_Artifacts_OnDisk: this rule targets staged exploit payloads, PCAP captures, and scripts on analyst or admin hosts that contain BRIDGE:BREAK-specific exploit URL fragments and Authorization header patterns. The condition is structured as any-of so a single unambiguous string from either the Lantronix chain (FsBrowser, ltrx_evo) or the Silex chain (redirect-URL-overflow probe) yields a hit while still allowing multi-indicator corroboration for high-confidence escalation. Fragment strings are narrow and codepoint-specific to minimize false positives against generic HTTP fuzzing corpora.

```text
rule BridgeBreak_Exploit_Artifacts_OnDisk
```

{

meta:

description = "Detects on-disk BRIDGE:BREAK exploit fragments (Lantronix EDS3000PS TFTP / ltrx_evo and Silex SD-330AC redirect URL)"

author = "1898 & Co. Threat Hunt"

date = "2026-04-22"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-02"

strings:

\$s_lantronix_fsbrowser = "FsBrowser" ascii wide

\$s_lantronix_host_inject = /host=\[A-Za-z0-9.%\]+\[;|\`\]/ ascii

\$s_lantronix_ltrx = "ltrx_evo" ascii wide

\$s_silex_redirect = /redirect=\[A-Za-z0-9%.\_-\]{200,}/ ascii

\$s_auth_admin = "Authorization: Basic YWRt" ascii

\$s_altpath_setup = /\\(setup|admin|system)\[^\\\]\*\sHTTP\\1\\\[01\]/ ascii

condition:

any of them

}

#### YARA Rule 2 (process memory) — BridgeBreak_Inflight_Exploit_Memory: this rule scans live process memory on admin hosts, analyst jump boxes, and Linux monitoring appliances for in-flight BRIDGE:BREAK exploit strings that would only appear transiently during active exploitation. The condition requires either a Lantronix-specific indicator AND the admin Authorization marker, or a Silex-specific long-redirect probe, reducing false-positive hits on documentation or training material resident in memory. Analysts should invoke with yara -p against curl, wget, python, and PowerShell processes, or use CrowdStrike Real Time Response to execute the rule across the admin host population.

```text
rule BridgeBreak_Inflight_Exploit_Memory
```

{

meta:

description = "Detects in-memory BRIDGE:BREAK exploit strings in live processes (transient indicators during active exploitation)"

author = "1898 & Co. Threat Hunt"

date = "2026-04-22"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10"

strings:

\$m_fsbrowser = "FsBrowser" ascii wide

\$m_ltrx = "ltrx_evo" ascii wide

\$m_host_inject = /host=\[A-Za-z0-9.%\]+\[;|\`\]/ ascii

\$m_silex_redirect = /redirect=\[A-Za-z0-9%.\_-\]{200,}/ ascii

\$m_auth_admin = "Authorization: Basic YWRt" ascii

\$m_shell_seed = /(\\bin\\(sh|bash)|nc\s+-e|\\dev\\tcp\\)/ ascii

condition:

( any of (\$m_fsbrowser, \$m_ltrx, \$m_host_inject) and \$m_auth_admin ) or

( \$m_silex_redirect ) or

( \$m_shell_seed and any of (\$m_fsbrowser, \$m_ltrx) )

}

#### YARA Rule 3 (firmware integrity) — BridgeBreak_Tampered_Firmware_Image: this rule inspects Silex SD-330AC firmware images staged on administrative hosts or captured in forensic images for markers associated with tampered firmware produced under CVE-2026-32958, including embedded shell-dropper strings adjacent to legitimate Silex header markers. The condition requires at least one Silex header string AND at least one attacker payload marker, which reliably excludes legitimate vendor images since unmodified images never contain the payload markers. Pair with vendor signing-key verification: a hit on this rule combined with a failed signature check is automatic escalation under Section 8 criterion 7.

```text
rule BridgeBreak_Tampered_Firmware_Image
```

{

meta:

description = "Detects markers of tampered Silex SD-330AC firmware images (CVE-2026-32958 abuse)"

author = "1898 & Co. Threat Hunt"

date = "2026-04-22"

reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32958"

strings:

\$h_silex_hdr = "SD-330AC" ascii wide

\$h_silex_amc = "AMCManager" ascii wide

\$p_shell = "/bin/sh" ascii

\$p_dropper = /(wget|curl|tftp)\s+-\[a-zA-Z\]?\s\*\[a-zA-Z0-9:\\.\]+/ ascii

\$p_persist = /(rc\\local|init\\d|cron|inittab)/ ascii

\$p_revsh = /(\\dev\\tcp\\|nc\s+-e|socat\s+exec:)/ ascii

condition:

any of (\$h_silex\_\*) and 2 of (\$p\_\*)

}

# Indicators of Compromise

Network IOCs (behavioral): HTTP requests to converter management IPs containing URL fragments FsBrowser or ltrx_evo with query strings that include shell metacharacters in the host parameter; HTTP requests carrying Authorization: Basic YWRt... headers against Lantronix management paths ending in setup, admin, or system; HTTP POST bodies to Silex SD-330AC login endpoints with redirect= parameters exceeding 200 bytes; outbound TFTP (UDP/69) originating from converter IP addresses; unexpected east-west traffic from converter IPs to PLC, historian, or medical-device VLANs.

Host IOCs (adjacent Windows hosts): 4688 process-creation events for curl.exe, wget.exe, python.exe, pwsh.exe, or powershell.exe with command lines matching the SIGMA 3 regex; 4104 PowerShell ScriptBlock events invoking Invoke-WebRequest or Invoke-RestMethod with Authorization headers containing admin; new executable writes matching rssilex\*.exe or similar firmware-push binaries outside the documented AMCManager install path.

OT/Operational IOCs: unexpected sysUpTime reset on a Silex SD-330AC outside the maintenance window; new CIP service codes, Modbus function codes, or OPC-UA method invocations originating from a converter IP and not present in the prior 30-day baseline; historian-level tag reading deviating from the 30-day baseline by more than 3 sigma coincident with a converter east-west flow; new asset fingerprint delta for a Silex or Lantronix converter in Claroty, Dragos, Nozomi, Armis, Tenable OT, or Forescout outside change-window approvals.

# False Positive Baseline

The following known-good patterns will appear during the hunt and must be suppressed or flagged as benign before escalation:

#### - Vendor-scheduled firmware distribution windows — pre-documented in the change management system — will legitimately produce TFTP and firmware POST traffic from administrative hosts to converter IPs.

Vulnerability scanning by Tenable.sc, Nessus, Qualys, Rapid7, or Claroty xDome enrichment pulls will generate sustained HTTP management-path requests from the scanner source IPs; scanner source addresses must be on the allowlist.

OT monitoring platform baseline-learning activities (Claroty CTD, Dragos, Nozomi, Armis, Tenable OT, Forescout) will generate light but persistent probes to OT assets including converters for device-fingerprinting purposes.

Approved remote-support sessions by OEM integrators often use AMC Manager over HTTPS from fixed vendor-egress IPs; these sessions will match admin-authorization heuristics and must be cross-referenced against active engagement tickets.

NTP, SNMP-monitoring, and Zabbix/SolarWinds polling of converters generates predictable low-rate management-plane traffic that will match SIGMA 1 destination selectors without matching the URL/Authorization selectors.

Automated certificate renewal and configuration backup scripts run from the configuration management server may invoke curl or PowerShell against converter management endpoints on schedule; waive these by source host and schedule signature.

# Escalation Criteria

Escalate to the incident response team when any of the following conditions are met:

1. A single HTTP request to a converter management IP matches both the BRIDGE:BREAK authentication-bypass URL suffix pattern and the admin Authorization header fingerprint from a source IP outside the documented admin allowlist.

2. Any outbound TFTP (UDP/69) connection originates from a converter management IP to an external or non-approved internal destination.

3. Any admin-host process-creation event matches the SIGMA 3 command-line regex from an account or host not participating in an active red-team engagement.

4. Any Silex SD-330AC reports a sysUpTime reset, firmware-change syslog, or cold/warmStart SNMP trap outside the documented maintenance window.

5. Any converter IP initiates a new east-west flow to a PLC, historian, medical device, or engineering workstation that is not present in the 30-day communication baseline.

6. Any historian tag reading deviates from its 30-day baseline by more than 3 standard deviations within five minutes of a converter-originated management-plane event.

#### 7. Any YARA hit on BridgeBreak_Tampered_Firmware_Image (Section 5 YARA Rule 3) against a firmware image staged for or applied to a Silex SD-330AC — correlate with vendor signing-key verification failure for automatic escalation.

8. Any YARA hit on BridgeBreak_Inflight_Exploit_Memory (Section 5 YARA Rule 2) against a live curl, wget, python, or PowerShell process on an admin host outside a documented penetration test.

#### 9. Any YARA hit on BridgeBreak_Exploit_Artifacts_OnDisk (Section 5 YARA Rule 1) against on-disk content on an admin or forensic host — correlate with the source and provenance of the file before closing.

# Hunt Completion Criteria and Reporting

The hunt is considered complete when (a) every converter asset identified in Section 1 has been queried for exploitation indicators across the full 30-day window, (b) every SIGMA, Snort/Suricata, and YARA rule in Section 5 has been executed against the relevant data source without producing an unresolved finding, (c) every OT monitoring platform export in Section 2 has been reviewed for baseline deviation, and (d) every false-positive pattern listed in Section 7 has been accounted for in the finding disposition.

The final hunt report must include: the enumerated converter inventory and firmware state; the source queries and commands executed with timestamps; the hit count per detection rule with per-hit disposition (true positive, false positive, indeterminate); any escalations triggered under Section 8 and their downstream incident ticket references; and a remediation status summary identifying devices still on vulnerable firmware and the planned upgrade date per device. Retain all hunt artifacts (PCAP, CSV exports, YARA output, platform exports) for a minimum of 180 days per organizational forensic retention policy.

# Advisory IoC Reference

| IOC Type | IOC |
|----|----|
| CVE | CVE-2025-67041 | CVSS v3.1 9.8 | Lantronix EDS3000PS firmware 3.1.0.0R2 | Unauthenticated OS command injection via TFTP client host parameter in Filesystem Browser; root RCE |
| CVE | CVE-2025-70082 | CVSS v3.1 9.8 | Lantronix EDS3000PS firmware 3.1.0.0R2 | Arbitrary code execution and sensitive information disclosure via ltrx_evo component |
| CVE | CVE-2025-67039 | CVSS v3.1 9.1 | Lantronix EDS3000PS firmware 3.1.0.0R2 | Authentication bypass via URL suffix and Authorization header containing admin |
| CVE | CVE-2025-67034 | CVSS v3.1 pending | Lantronix EDS5000 firmware 2.1.0.0R3 | BRIDGE:BREAK companion flaw in EDS5000; addressed by firmware 2.2.0.0R1 |
| CVE | CVE-2025-67035 | CVSS v3.1 pending | Lantronix EDS5000 firmware 2.1.0.0R3 | BRIDGE:BREAK companion flaw in EDS5000; addressed by firmware 2.2.0.0R1 |
| CVE | CVE-2025-67036 | CVSS v3.1 pending | Lantronix EDS5000 firmware 2.1.0.0R3 | BRIDGE:BREAK companion flaw in EDS5000; addressed by firmware 2.2.0.0R1 |
| CVE | CVE-2025-67037 | CVSS v3.1 pending | Lantronix EDS5000 firmware 2.1.0.0R3 | BRIDGE:BREAK companion flaw in EDS5000; addressed by firmware 2.2.0.0R1 |
| CVE | CVE-2025-67038 | CVSS v3.1 pending | Lantronix EDS5000 firmware 2.1.0.0R3 | BRIDGE:BREAK companion flaw in EDS5000; addressed by firmware 2.2.0.0R1 |
| CVE | CVE-2026-32955 | CVSS v3.1 8.8 | Silex SD-330AC firmware 1.42 and earlier | Authenticated stack-based buffer overflow via login redirect URL |
| CVE | CVE-2026-32956 | CVSS v3.1 9.8 | Silex SD-330AC firmware 1.42 and earlier | Unauthenticated heap-based buffer overflow via login redirect URL |
| CVE | CVE-2026-32957 | CVSS v3.1 5.3 | Silex SD-330AC firmware 1.42 and earlier | Unauthenticated arbitrary file upload to temporary storage |
| CVE | CVE-2026-32958 | CVSS v3.1 6.5 | Silex SD-330AC firmware 1.42 and earlier | Hard-coded firmware signing key enables tampered firmware application |
| CVE | CVE-2026-32959 | CVSS v3.1 5.9 | Silex SD-330AC firmware 1.42 and earlier | Weak encryption; constant keystream enables man-in-the-middle data theft |
| CVE | CVE-2026-32960 | CVSS v3.1 6.5 | Silex SD-330AC firmware 1.42 and earlier | Authentication bypass via retained-credential reuse in crafted packet |
| CVE | CVE-2026-32961 | CVSS v3.1 5.3 | Silex SD-330AC firmware 1.42 and earlier | Heap overflow resulting in DoS or potential RCE |
| CVE | CVE-2026-32962 | CVSS v3.1 5.3 | Silex SD-330AC firmware 1.42 and earlier | Unauthenticated configuration modification (missing authentication) |
| CVE | CVE-2026-32963 | CVSS v3.1 6.1 | Silex SD-330AC firmware 1.42 and earlier | Reflected cross-site scripting on system status page |
| CVE | CVE-2026-32964 | CVSS v3.1 6.5 | Silex SD-330AC firmware 1.42 and earlier | Unauthenticated configuration injection inserting arbitrary entries |
| CVE | CVE-2026-32965 | CVSS v3.1 7.5 | Silex SD-330AC firmware 1.42 and earlier | Insecure default initialization; null administrative password allows takeover |
| CVE | CVE-2015-5621 | CVSS v3.1 7.5 | Silex SD-330AC bundled SNMP agent | Legacy net-snmp DoS; terminates SNMP agent abnormally |
| CVE | CVE-2024-24487 | CVSS v3.1 5.3 | Silex SD-330AC firmware 1.42 and earlier | Unauthenticated device reboot causing denial of service |
| Threat Actor | None specifically attributed — BRIDGE:BREAK was discovered and coordinated-disclosed by Forescout Research Vedere Labs; no named actor observed exploiting the chain at disclosure |
| Malware | None published — no malware family has been attributed to BRIDGE:BREAK exploitation at time of disclosure |
| Network IOC | None published in source material — monitor https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-02 and https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10 for exploitation indicators |
| File IOC | None published in source material — monitor Forescout Vedere Labs and vendor advisories for released PoC artifacts |
| Behavioral | HTTP requests to converter management IPs containing URL fragments FsBrowser or ltrx_evo with shell metacharacters in the host parameter |
| Behavioral | HTTP requests carrying Authorization: Basic YWRt... headers against Lantronix management paths ending in setup, admin, or system |
| Behavioral | HTTP POST bodies to Silex SD-330AC login endpoints with redirect= parameters exceeding 200 bytes |
| Behavioral | Outbound TFTP (UDP/69) originating from converter IP addresses |
| Behavioral | New east-west traffic from converter IPs to PLC, historian, medical-device, or engineering-workstation VLANs absent from the 30-day baseline |
| Behavioral | Silex SD-330AC sysUpTime reset, firmware-change syslog, or cold/warmStart SNMP trap outside documented maintenance windows |
| Behavioral | New CIP service codes, Modbus function codes, or OPC-UA method invocations originating from converter IP outside 30-day baseline |
| Behavioral | 4688 process-creation events for curl/wget/python/pwsh on admin hosts with command lines containing FsBrowser, ltrx_evo, host= with shell metacharacters, or Authorization Basic YWRt |
