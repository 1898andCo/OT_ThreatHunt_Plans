# Threat Hunt Plan: ICSA-26-078-08 — Automated Logic WebCTRL BACnet Protocol Exploitation (CVE-2026-24060 / CVE-2026-32666 / CVE-2026-25086)

> **Revision 1.0** | 24 March 2026

# Hunt Objective and Scope

This hunt targets active and historical exploitation of three vulnerabilities disclosed in CISA ICS Advisory ICSA-26-078-08 affecting Automated Logic WebCTRL Premium Server versions prior to v8.5. The hunt seeks to identify: (1) passive interception of cleartext BACnet traffic from the building automation network (CVE-2026-24060, CVSS v3.1 9.1 Critical); (2) injection of spoofed BACnet packets to issue unauthorized commands to WebCTRL or connected controllers (CVE-2026-32666, CVSS v3.1 7.5 High); and (3) port-binding impersonation of the WebCTRL service by a rogue process on the WebCTRL host (CVE-2026-25086, CVSS v3.1 7.7 High).

The environment in scope includes all Windows hosts running WebCTRL Premium Server, all network segments carrying BACnet/IP traffic on UDP/TCP port 47808 and BACnet/SC on TCP port 9001, all BACnet-connected controllers and field devices, and any IT network segments from which the WebCTRL host or BACnet segments are reachable. The retroactive hunt window is 90 days prior to hunt initiation. Live monitoring should be maintained continuously until all affected hosts are upgraded to WebCTRL v8.5 with BACnet Secure Connect (BACnet/SC) enabled.

# Hypotheses and Hunt Procedures

## Hypothesis 1

An attacker has passively captured and analyzed cleartext BACnet traffic on the building automation network, observable as network packet capture tools running on or near the WebCTRL host or BACnet segment, or as pcap files written to disk on adjacent hosts.

### MITRE ATT&CK

Collection \| T1040 — Network Sniffing \| An adversary on the same network segment as WebCTRL's BACnet interface can passively capture all unencrypted BACnet service traffic to extract controller addresses, object data, file positions, and proprietary update formats without sending any packets, exploiting CVE-2026-24060.

### Collection Queries

#### CrowdStrike Falcon FQL — Packet capture tool execution

```text
#event_simpleName = "ProcessRollup2"
| in(FileName, values=["Wireshark.exe","tshark.exe","dumpcap.exe","NetworkMiner.exe","rawcap.exe","windump.exe","pktmon.exe"])
| table([ComputerName, timestamp, FileName, CommandLine, ParentBaseFileName, ImageFileName])
// time range: 90 days retroactive
```
#### CrowdStrike Falcon FQL — New pcap/capture file written to disk

```text
#event_simpleName = "NewExecutableWritten"
| TargetFileName = /\\(pcap|pcapng|cap|etl)\$/i
| table([ComputerName, timestamp, TargetFileName, FilePath])
// time range: 90 days retroactive
```
#### tcpdump BPF — Capture all BACnet/IP traffic on the building automation segment

```bash
tcpdump -i eth0 -w /tmp/bacnet_capture_%Y%m%d_%H%M%S.pcap -G 3600 -C 100 "udp port 47808 or tcp port 47808 or tcp port 9001"
```
Replace eth0 with the interface facing the BACnet network. Port 47808 = BACnet/IP; port 9001 = BACnet/SC.

#### Datadog Log Search — Packet capture tool execution (Windows)

```text
source:windows message:("Wireshark" OR "tshark" OR "dumpcap" OR "pktmon" OR "NetworkMiner")
// time range: 90 days retroactive to current
```
Analytics: Table view; group by host; sort by count descending.

***Data source gap:*** If Windows Event Forwarding does not include process creation (Event ID 4688) logs, this query will not surface results. Fallback — Live Process Monitoring (Infrastructure \> Processes): command:wireshark OR command:tshark OR command:dumpcap.

#### Datadog Monitor — Packet capture tool detection

```text
Type: Log Alert
Query: source:windows message:("Wireshark" OR "tshark" OR "dumpcap" OR "pktmon" OR "NetworkMiner" OR "rawcap")
Evaluation window: last 5 minutes
Alert condition: count > 0
Message: "ALERT: Packet capture tool launched on Windows host — possible BACnet traffic interception — immediate investigation required @soc-channel"
```
Prerequisites: Windows Event Forwarding with process creation (Event ID 4688) or Sysmon Event ID 1 forwarded to Datadog

#### Windows Event IDs to Collect

Event ID 4688 (Process Creation) — requires Advanced Audit Policy: Process Creation enabled

Event ID 4663 (File Object Access) — capture file writes to disk

Sysmon Event ID 1 (Process Create) — full command line and parent image

Sysmon Event ID 11 (FileCreate) — pcap, pcapng, etl file creation

#### PowerShell collection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-90)} |
Where-Object { \$_.Message -match 'Wireshark|tshark|dumpcap|NetworkMiner|pktmon|windump' } |
Select-Object TimeCreated, Message |
Export-Csv -Path "C:\hunt\capture_tools_4688.csv" -NoTypeInformation
```
***OT Data Collection:*** Export switch port traffic counters via SNMP for the interface connecting to the BACnet segment. Elevated unicast input counters on the BACnet switch port from a non-controller source address indicate passive capture activity.

```powershell
snmpget -v2c -c <community> <switch_ip> IF-MIB::ifInOctets.<interface_index>
snmpget -v2c -c <community> <switch_ip> IF-MIB::ifInUcastPkts.<interface_index>
```
#### YARA file-system scan

```text
yara -r C:\hunt\rules\bacnet_capture_tools.yar C:\\ >> C:\hunt\yara_capture_hits.txt 2>&1
```
### Analysis Queries

#### CrowdStrike Falcon FQL — Rarity analysis of processes on WebCTRL host

```text
#event_simpleName = "ProcessRollup2"
| ComputerName = /webctr/i
| groupBy([ComputerName, FileName, ParentBaseFileName, CommandLine], function=count(), limit=100000)
| sort(_count, order=asc, limit=50)
// time range: 90 days retroactive — asc = rarest first, most suspicious
```
#### CrowdStrike Falcon FQL — pcap files written on any endpoint

```text
#event_simpleName = "NewExecutableWritten"
| TargetFileName = /\\(pcap|pcapng|cap)\$/i
| groupBy([ComputerName, TargetFileName, FilePath], function=count(), limit=100000)
| sort(_count, order=asc, limit=50)
// time range: 90 days retroactive
```
#### Wireshark display filter — DNS queries for capture tool update domains

dns.qry.name contains "wireshark" or dns.qry.name contains "live.sysinternals" or dns.qry.name contains "cloudshark"

```bash
tshark equivalent:
tshark -r bacnet_capture.pcap -Y 'dns.qry.name contains "wireshark" or dns.qry.name contains "cloudshark"' -T fields -e frame.time -e ip.src -e dns.qry.name
```
#### Datadog Log Analytics — Timeline of capture tool events

```text
source:windows message:("Wireshark" OR "tshark" OR "dumpcap" OR "pktmon")
// Analytics: Timeseries view; group by host; time range: 90 days to current
```
#### Datadog Audit Trail

```text
source:datadog @evt.category:user_access @evt.name:login
// Correlate login events with timestamps of capture tool executions identified above
```
#### Datadog CloudTrail query (if WebCTRL runs in hybrid/cloud environment)

```text
source:cloudtrail @evt.name:(DescribeInstances OR GetObject) -@network.client.ip:10.\* -@network.client.ip:172.16.\*
// Analytics: Table view; group by @network.client.ip, @userIdentity.arn; time range: 90 days
```
#### Windows Event Log — Sysmon file creation (pcap files)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=11; StartTime=(Get-Date).AddDays(-90)} |
Where-Object { \$_.Message -match '\\pcap|\\pcapng|\\cap' } |
Select-Object TimeCreated, Message |
Export-Csv -Path "C:\hunt\pcap_files_sysmon.csv" -NoTypeInformation
```
***OT Analysis:*** Correlate SNMP switch port byte counters on the BACnet segment interface with scheduled operational hours. A baseline deviation exceeding 20% in received bytes on a non-PLC source port during off-hours warrants investigation as passive capture activity. Export Claroty, Dragos, or Nozomi asset timeline for the BACnet segment and identify any new device registrations (new BACnet device instance numbers) that do not correspond to authorized controllers.

#### YARA memory scan

```powershell
Get-Process | ForEach-Object { yara C:\hunt\rules\bacnet_capture_tools.yar \$_.Id 2>\$null } >> C:\hunt\yara_capture_memory_hits.txt
```
CrowdStrike RTR: Run above command via Falcon Real Time Response on the WebCTRL host.

## Hypothesis 2

An attacker has injected spoofed BACnet packets into the building automation network (CVE-2026-32666), observable as anomalous BACnet control commands originating from unexpected source IP addresses or as unauthorized WriteProperty operations against controller objects outside normal scheduling windows.

### MITRE ATT&CK

Defense Evasion / ICS Impact \| T1036 — Masquerading \| T0831 — Manipulation of Control \| An attacker with access to the BACnet segment crafts fraudulent BACnet packets that are accepted as authentic by WebCTRL and connected controllers (CVE-2026-32666), enabling unauthorized write operations that can alter setpoints, disable alarms, or manipulate control outputs without valid credentials.

### Collection Queries

#### tcpdump BPF — Capture BACnet WriteProperty and DeviceCommunicationControl packets

```bash
tcpdump -i eth0 -w /tmp/bacnet_writes_%Y%m%d_%H%M%S.pcap -G 1800 -C 50 "udp port 47808 and (udp[10:1] = 0x0f or udp[10:1] = 0x1c)"
```
BACnet APDU: 0x0f = WriteProperty; 0x1c = DeviceCommunicationControl. Replace eth0 with the BACnet-facing interface.

#### tcpdump BPF — Capture BACnet Who-Is broadcasts (device discovery/scanning)

```bash
tcpdump -i eth0 -w /tmp/bacnet_discovery_%Y%m%d_%H%M%S.pcap "udp port 47808 and udp[10:1] = 0x10"
```
BACnet APDU 0x10 = Who-Is unconfirmed service.

#### CrowdStrike Falcon FQL — DNS queries from building automation hosts to external domains

```text
#event_simpleName = "DnsRequest"
| DomainName = /bacnet|automatedlogic|webctr/i
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,TargetProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]), limit=100000)},
field=[aid,ContextProcessId], key=[aid,TargetProcessId],
include=[ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]
)
| table([ComputerName, DomainName, IpAddress, RequestType, FileName, CommandLine, ParentBaseFileName])
// time range: 90 days retroactive
```
#### Datadog Log Search — BACnet write anomalies in application logs

```text
source:windows message:("BACnet" OR "WriteProperty" OR "DeviceCommunicationControl") status:error
// time range: 90 days retroactive to current
```
#### Windows Event IDs

Event ID 5156 (Windows Filtering Platform — permitted connection) — BACnet port connections from unexpected hosts

Event ID 5157 (WFP blocked connection)

Event ID 4624/4625 (Logon success/failure) — lateral movement onto BACnet segment hosts

#### PowerShell collection

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-90)} |
Where-Object { \$_.Message -match ':47808' } |
Select-Object TimeCreated, Message |
Export-Csv -Path "C:\hunt\bacnet_wfp_5156.csv" -NoTypeInformation
```
***OT Data Collection:*** Export BACnet change-of-value log from the historian (Wonderware, OSIsoft PI, ICONICS, or similar). Filter for WriteProperty operations on commandable objects (analogOutput, binaryOutput) outside normal scheduled hours. Export Claroty, Dragos, or Nozomi BACnet device session logs for the hunt window.

#### YARA file-system scan (BACnet crafting tool artifacts)

```text
yara -r C:\hunt\rules\bacnet_capture_tools.yar C:\\ >> C:\hunt\yara_spoofing_file_hits.txt 2>&1
```
### Analysis Queries

#### CrowdStrike Falcon FQL — Network connections to BACnet port from endpoint processes

```text
#event_simpleName = "NetworkConnectIP4"
| RemotePort = 47808
| join(
query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]), limit=100000)},
field=[aid,RawProcessId],
include=[ImageFileName,FileName,CommandLine,ParentBaseFileName,AuthenticationId]
)
| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName])
// time range: 90 days retroactive
```
#### CrowdStrike Falcon FQL — Top BACnet-port source IPs for baseline deviation detection

```text
#event_simpleName = "NetworkConnectIP4"
| RemotePort = 47808
| top([ComputerName, RemoteAddressIP4, FileName], limit=50)
// time range: 90 days retroactive
```
#### Wireshark display filter — BACnet WriteProperty from non-baseline sources

(bacnet.confirmed_service == 15) and !(ip.src == \<authorized_webctr_ip\>)

```bash
tshark equivalent:
tshark -r bacnet_writes.pcap -Y "(bacnet.confirmed_service == 15) and !(ip.src == <webctr_host_ip>)" -T fields -e frame.time -e ip.src -e ip.dst -e bacnet.confirmed_service
```
#### Wireshark display filter — BACnet Who-Is flood (high-rate scanning)

bacnet.unconfirmed_service == 8

```bash
tshark rate check:
tshark -r bacnet_discovery.pcap -Y "bacnet.unconfirmed_service == 8" -T fields -e frame.time -e ip.src | awk -F'\t' '{print \$2}' | sort | uniq -c | sort -rn | head -20
```
Flag any source IP emitting more than 50 Who-Is packets in a 10-second window as scanning activity.

#### Datadog Log Analytics — BACnet port connection sources

```text
source:windows @network.client.port:47808
// Analytics: Table view; group by @network.client.ip; time range: 90 days to current
```
#### Datadog Audit Trail

```text
source:datadog @evt.category:user_access @evt.name:login
// Correlate admin login events with timestamps of BACnet anomaly windows identified above
```
#### Datadog Monitor

```text
Type: Log Alert
Query: source:windows @network.client.port:47808 !(host:<webctr_hostname>)
Evaluation window: last 15 minutes
Alert condition: count > 10
Message: "ALERT: Unexpected host communicating on BACnet port 47808 — possible packet spoofing (CVE-2026-32666) — immediate investigation required @soc-channel"
```
Prerequisites: Windows Firewall (WFP) audit logs forwarded to Datadog; Event ID 5156 enabled via Advanced Audit Policy

#### Windows Event Log — WFP connections to BACnet port

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-90)} |
Where-Object { \$_.Message -match ':47808' } |
Export-Csv -Path "C:\hunt\bacnet_wfp_analysis.csv" -NoTypeInformation
```
***OT Network Analysis:*** Pull 90-day trend from the historian for any controller object that received a WriteProperty operation outside the normal maintenance schedule. Flag any write that placed an analogOutput or binaryOutput beyond its documented operational range (maxPresValue / minPresValue). Correlate SNMP switch port counters showing unicast traffic from unexpected source MACs on the BACnet VLAN.

#### YARA memory scan

```powershell
Get-Process | ForEach-Object { yara C:\hunt\rules\bacnet_impersonation.yar \$_.Id 2>\$null } >> C:\hunt\yara_spoofing_memory_hits.txt
```
## Threat Actor Profile

The vulnerabilities in ICSA-26-078-08 require low-to-moderate technical sophistication and no specific named threat actors have been attributed to exploitation at this time. Three plausible adversary categories apply to this advisory.

Opportunistic attackers and building automation researchers: CVE-2026-24060 (cleartext BACnet) is exploitable by anyone with a network-connected laptop and Wireshark. This access profile matches security researchers, disgruntled insiders with IT access, and opportunistic attackers conducting post-compromise reconnaissance. Objectives are typically passive — mapping controller addresses, operational schedules, and object hierarchies rather than causing immediate disruption.

Nation-state and advanced persistent threat actors targeting critical facilities: Adversaries with documented interest in building automation and physical infrastructure — including groups such as Volt Typhoon (pre-positioned access in critical infrastructure) and Sandworm (Ukraine energy sector intrusions) — could leverage CVE-2026-32666 and CVE-2026-25086 as part of a multi-stage campaign targeting data centers, hospitals, or government facilities. These actors typically establish long-term access and could use BACnet spoofing to manipulate HVAC or power controls as a precursor to a broader disruption operation. Access path: IT-OT pivot via compromised IT workstation or VPN credentials; TTP: T1040, T1036, T0831, T0832.

Insider threats: A malicious insider with physical or network access to the building automation environment could exploit CVE-2026-25086 on the WebCTRL host to impersonate the service and manipulate controller communications without leaving attribution traces tied to their normal account credentials.

## Data Sources Required

***Network:*** Full-packet capture (PCAP) from the BACnet/IP network segment (UDP 47808 and TCP 9001); NetFlow or IPFIX records from the distribution switch serving the BACnet segment; firewall connection logs between IT and OT network zones.

***Endpoint:*** CrowdStrike Falcon process telemetry (ProcessRollup2, NetworkConnectIP4, DnsRequest, RegGenericValueUpdate, AsepValueUpdate, NewExecutableWritten) on all Windows hosts running WebCTRL; Windows Security Event Log (IDs 4688, 4624, 4625, 5156, 5157, 7045); Sysmon Event IDs 1, 3, 11 on WebCTRL hosts.

***OT/ICS:*** BACnet historian change-of-value logs for all output and commandable objects; SCADA alarm logs for out-of-range setpoints or unauthorized write operations; BACnet router device tables for unexpected device instance registrations; OT network monitoring platform (Claroty, Dragos, Nozomi) alerts for anomalous device discovery or write activity.

***Vendor/device logs:*** WebCTRL application event logs (installation directory under logs/); Automated Logic controller communication logs (GCM, MEC, or similar device type); building automation gateway syslog exports.

## Detection Signatures

#### SIGMA Rule 1 — Network Packet Capture Tool Launched (BACnet Sniffing Risk)

This rule targets the process creation phase of CVE-2026-24060 exploitation, where an attacker launches a capture tool on or near a host with BACnet network access to passively record cleartext BACnet traffic. The OR structure across six tool binaries ensures breadth across common open-source and Windows-native capture utilities. False-positive mitigation is achieved by suppressing known-authorized maintenance sessions via the falsepositives field rather than in the condition, preserving sensitivity for unanticipated tool usage.

```yaml
title: Network Packet Capture Tool Launched — BACnet Sniffing Risk (CVE-2026-24060)
id: 3a1f4b2c-9e0d-4a7f-b1c2-8d3e5f601234
status: experimental
description: Detects execution of known network packet capture tools on hosts that may carry BACnet network access, indicating potential passive interception of cleartext BACnet traffic per CVE-2026-24060.
references:
```
\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-08

\- https://nvd.nist.gov/vuln/detail/CVE-2026-24060

```yaml
author: 1898 & Co.
date: 2026-03-24
tags:
```
\- attack.collection

\- attack.t1040

```yaml
logsource:
```
category: process_creation

product: windows

```yaml
detection:
selection:
```
Image\|endswith:

\- '\Wireshark.exe'

\- '\tshark.exe'

\- '\dumpcap.exe'

\- '\NetworkMiner.exe'

\- '\rawcap.exe'

\- '\windump.exe'

\- '\pktmon.exe'

```yaml
condition: selection
falsepositives:
```
\- Authorized network engineers performing scheduled maintenance captures

\- Security team conducting approved packet analysis

```yaml
level: high
```
#### SIGMA Rule 2 — Non-WebCTRL Process Binding to WebCTRL Service Port (CVE-2026-25086)

This rule targets the port-binding phase of CVE-2026-25086 exploitation, where an unexpected process establishes a network connection on the WebCTRL service port. The filter_legitimate block suppresses known-good WebCTRL and Automated Logic process names; the condition requires a connection on the sensitive port combined with the absence of a legitimate image name. False-positive risk from authorized third-party BACnet integrations is mitigated by the filter and noted in the falsepositives field.

```yaml
title: Non-WebCTRL Process Connecting on WebCTRL Service Port — Possible Impersonation (CVE-2026-25086)
id: 7c2d0e1a-4b5f-4c8d-a2e3-1f9c6b720abc
status: experimental
description: Detects any Windows process establishing a network connection on port 47808 or 9001 on a WebCTRL host where the process image does not match the expected WebCTRL service. Indicates potential port-binding impersonation per CVE-2026-25086.
references:
```
\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-08

\- https://nvd.nist.gov/vuln/detail/CVE-2026-25086

```yaml
author: 1898 & Co.
date: 2026-03-24
tags:
```
\- attack.defense_evasion

\- attack.t1036.004

```yaml
logsource:
```
category: network_connection

product: windows

```yaml
detection:
selection:
```
DestinationPort\|contains:

\- '47808'

\- '9001'

filter_legitimate:

Image\|contains:

\- 'WebCTRL'

\- 'webctr'

\- 'AutomatedLogic'

```yaml
condition: selection and not filter_legitimate
falsepositives:
```
\- Authorized third-party BACnet integration software (Niagara, Tridium, Metasys) installed on the same host

\- BACnet/SC test tools used by network engineers during authorized testing

```yaml
level: critical
```
#### SIGMA Rule 3 — New Windows Service Installed on WebCTRL Host (Persistence)

This rule targets persistence activity following initial exploitation, where an attacker installs a new Windows service on the WebCTRL host to maintain access or persistently bind to the WebCTRL port. Event ID 7045 fires on any service installation; pairing this with host-scoping in the logsource or via SIEM filter to WebCTRL hostnames reduces scope. False-positive mitigation relies on correlation with authorized change records, noted in falsepositives.

```yaml
title: New Windows Service Installed on WebCTRL Server
id: 5f1a3c9b-2e4d-4f1a-b8c3-0d7e9a241bc5
status: experimental
description: Detects installation of a new Windows service on a host running WebCTRL, which may indicate attacker persistence or a persistent port-binding process following exploitation of CVE-2026-25086.
references:
```
\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-08

\- https://nvd.nist.gov/vuln/detail/CVE-2026-25086

```yaml
author: 1898 & Co.
date: 2026-03-24
tags:
```
\- attack.persistence

\- attack.t1543.003

```yaml
logsource:
```
product: windows

service: system

```yaml
detection:
selection:
```
EventID: 7045

```yaml
condition: selection
falsepositives:
```
\- Authorized WebCTRL upgrades or component installations performed by facilities IT

\- Legitimate third-party building automation integration software installations

```yaml
level: high
```
#### Snort/Suricata Rule 1 — BACnet Who-Is Broadcast Flood (Device Discovery Scan)

```text
alert udp any any -> any 47808 (
```
msg:"BACNET-ICS BACnet Who-Is Broadcast Flood — Possible Device Discovery Scan (CVE-2026-32666)";

content:"\|81 0b\|"; offset:0; depth:2;

threshold:type both, track by_src, count 50, seconds 10;

classtype:attempted-recon;

sid:9800001; rev:1;

reference:url,www.cisa.gov/news-events/ics-advisories/icsa-26-078-08;

metadata:affected_product WebCTRL, cve CVE-2026-32666, created_at 2026-03-24;

```text
)
```
#### Snort/Suricata Rule 2 — BACnet WriteProperty from Untrusted Source

```text
alert udp !\$BACNET_TRUSTED_HOSTS any -> \$BACNET_SERVERS 47808 (
```
msg:"BACNET-ICS BACnet WriteProperty from Untrusted Source — Possible Spoofed Command Injection (CVE-2026-32666)";

content:"\|81 0a\|"; offset:0; depth:2;

byte_test:1,&,0x00,10,relative;

classtype:protocol-command-decode;

sid:9800002; rev:1;

reference:url,www.cisa.gov/news-events/ics-advisories/icsa-26-078-08;

metadata:affected_product WebCTRL, cve CVE-2026-32666, created_at 2026-03-24;

```text
)
```
Set \$BACNET_TRUSTED_HOSTS to authorized WebCTRL and controller management station IP ranges. Set \$BACNET_SERVERS to the WebCTRL host and BACnet router IPs.

#### YARA Rule 1 — BACnet Capture Tool Artifacts (File/Disk Scan)

This rule targets file-system artifacts left by network packet capture tools that an adversary would use to exploit CVE-2026-24060 (passive BACnet sniffing). The condition uses an OR structure across three tool families (Wireshark/dumpcap, WinDump, NetworkMiner) and the npcap driver string, ensuring coverage across the most common Windows-based capture utilities. The filesize gate (under 100 MB) excludes captured packet files themselves, which may contain the same string signatures but are not indicators of the tool being present. The hex pattern for the BACnet port (0xBAC0) is included as an additional signal when found alongside npcap strings.

```yara
rule BACnet_Capture_Tool_Artifacts {
```
meta:

description = "Detects file-system artifacts of network packet capture tools used for cleartext BACnet traffic sniffing (CVE-2026-24060)"

author = "1898 & Co."

date = "2026-03-24"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-08"

strings:

\$s1 = "Wireshark" ascii wide nocase

\$s2 = "dumpcap.exe" ascii wide nocase

\$s3 = "tshark.exe" ascii wide nocase

\$s4 = "WinDump" ascii wide nocase

\$s5 = "windump.exe" ascii wide nocase

\$s6 = "NetworkMiner" ascii wide nocase

\$s7 = "NetworkMiner.exe" ascii wide nocase

\$s8 = "NPCAP" ascii wide nocase

\$s9 = "\\Device\\NPF\_" ascii wide

\$h1 = { BA C0 }

condition:

filesize \< 100MB and (

(any of (\$s1,\$s2,\$s3)) or

(any of (\$s4,\$s5)) or

(any of (\$s6,\$s7)) or

(\$s8 and \$h1) or

(\$s9 and \$h1)

```text
)
}
```
#### File scan command

```text
yara -r C:\hunt\rules\bacnet_capture_tools.yar C:\\ >> C:\hunt\yara_capture_hits.txt 2>&1
```
#### YARA Rule 2 — BACnet Spoofing and Impersonation Memory Artifacts

This rule targets in-memory indicators of tools used to craft and inject spoofed BACnet packets (CVE-2026-32666) or bind to the WebCTRL port for service impersonation (CVE-2026-25086). The condition requires the BACnet port magic byte sequence alongside at least one additional indicator from three categories: raw socket API calls (indicative of crafted packet transmission), port-binding API calls (indicative of CVE-2026-25086 exploitation), or known BACnet packet crafting library strings. The two-signal requirement reduces false positives from legitimate BACnet client applications that may reference these APIs in non-malicious contexts; a legitimate BACnet client does not typically use SOCK_RAW or SO_REUSEADDR alongside the BACnet port marker.

```yara
rule BACnet_Spoofing_Impersonation_Memory {
```
meta:

description = "Detects in-memory indicators of BACnet packet crafting or port-binding impersonation tools (CVE-2026-32666, CVE-2026-25086)"

author = "1898 & Co."

date = "2026-03-24"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-078-08"

strings:

\$b1 = { 81 0B }

\$b2 = { 81 0A }

\$h1 = { BA C0 }

\$s1 = "SOCK_RAW" ascii wide nocase

\$s2 = "sendto" ascii wide nocase

\$s3 = "WSASendTo" ascii wide nocase

\$s4 = "bind(" ascii wide nocase

\$s5 = "SO_REUSEADDR" ascii wide nocase

\$s6 = "SO_EXCLUSIVEADDRUSE" ascii wide nocase

\$l1 = "BACnet-stack" ascii wide nocase

\$l2 = "bacnet4j" ascii wide nocase

\$l3 = "yabe" ascii wide nocase

condition:

\$h1 and (

((\$b1 or \$b2) and any of (\$s1,\$s2,\$s3)) or

(any of (\$s4,\$s5,\$s6)) or

any of (\$l1,\$l2,\$l3)

```text
)
}
```
#### Memory scan command

```powershell
Get-Process | ForEach-Object { yara C:\hunt\rules\bacnet_impersonation.yar \$_.Id 2>\$null } >> C:\hunt\yara_impersonation_memory_hits.txt
```
CrowdStrike RTR: Deploy above command via Falcon Real Time Response for remote scanning without requiring console access to the WebCTRL host.

## Indicators of Compromise

***Network IOCs:*** No specific IP addresses, domains, URLs, or C2 infrastructure have been published in source material for ICSA-26-078-08. Monitor the Automated Logic security commitment page and CISA ICS alert feeds for IoC publications as exploitation activity is reported.

***File IOCs:*** No specific file hashes or malware sample identifiers have been associated with exploitation of these vulnerabilities at the time of this hunt plan. Monitor NVD and Automated Logic vendor feeds for artifact publications.

#### OT/Operational IOCs — Behavioral indicators

BACnet WriteProperty operations on controller output objects from source IP not in authorized WebCTRL host list

Who-Is broadcast rate exceeding 50 packets per 10 seconds from non-controller source on the BACnet segment

Multiple processes simultaneously bound to UDP or TCP port 47808 on the WebCTRL host

New Windows service (Event ID 7045) installed on the WebCTRL host outside a scheduled change window

pcap or pcapng files created on the WebCTRL host or any IT host with BACnet segment access

WebCTRL application log entries indicating port-already-in-use or connection reset errors

Controller analog output or binary output values deviating from setpoint range without operator-initiated write

## False Positive Baseline

- Authorized WebCTRL administrators running Wireshark or tshark during network troubleshooting sessions — verify against the change management record and confirm the initiating account matches the authorized administrator list.

- BACnet Who-Is discovery broadcasts from newly commissioned controllers during installation or re-addressing — correlate with the project commissioning schedule and validate the source device is in the authorized device registry.

- Third-party BACnet integration software (Niagara Framework, Tridium, Johnson Controls Metasys) installed on the same WebCTRL host, which may legitimately bind to BACnet ports — verify the process image path matches the installed integration package and that the installation is documented in the authorized software inventory.

- IT network monitoring tools (SolarWinds PRTG, Nagios, or similar) performing discovery scans across building automation subnets — review scan scope and confirm BACnet ports are excluded or that scan source IPs are in the trusted host list.

- WebCTRL upgrade or patch installation processes creating new Windows services on the host — validate process hashes against the Automated Logic release package hash list and confirm the installation window is in the approved change log.

## Escalation Criteria

- Any CrowdStrike detection or SIGMA Rule 1 hit for a packet capture tool (Wireshark, tshark, dumpcap, NetworkMiner, pktmon) executing on the WebCTRL host or any host on the BACnet segment outside an authorized maintenance window.

- Any BACnet WriteProperty operation observed from a source IP not in the authorized WebCTRL host list, as identified by Wireshark or tshark analysis of captured BACnet segment traffic.

- Any YARA hit on BACnet_Capture_Tool_Artifacts against file-system scan of the WebCTRL host or any endpoint with BACnet segment access.

- Any YARA hit on BACnet_Spoofing_Impersonation_Memory against in-memory scan of any process on the WebCTRL host.

- Two or more processes simultaneously observed bound to TCP or UDP port 47808 on the WebCTRL host, as identified by the PowerShell Get-NetTCPConnection listener audit.

- Any new Windows service (Event ID 7045) installed on the WebCTRL host that cannot be correlated to an authorized change record within 30 minutes of detection.

- Any controller analog output or binary output object receiving a WriteProperty command placing it outside its documented operating range, as identified by historian change-of-value log analysis.

## Hunt Completion Criteria and Reporting

The hunt is complete when all of the following conditions have been satisfied: all Windows hosts running WebCTRL Premium Server have been inventoried with current version and BACnet/SC enablement status recorded; the full 90-day retroactive query window has been executed for all CrowdStrike FQL, Windows Event Log, and BACnet segment capture-based queries; all YARA file-system and memory scans have been completed on WebCTRL hosts and results reviewed; and all BACnet segment network captures have been analyzed for anomalous WriteProperty sources and Who-Is flood patterns. The completion report must contain: the WebCTRL host inventory with version and patch status; all CrowdStrike FQL query outputs including rarity analysis results and any anomalous findings; YARA scan results with all hits documented and disposition recorded; BACnet segment traffic analysis results with authorized versus unexpected source IP enumeration; historian change-of-value analysis summary; and a recommended remediation timeline for the upgrade to WebCTRL v8.5 aligned to the operational change window schedule. Section 8 Escalation Criteria includes two conditions directly tied to YARA rule definitions in Section 5: Escalation Criterion 3 is tied to BACnet_Capture_Tool_Artifacts, and Escalation Criterion 4 is tied to BACnet_Spoofing_Impersonation_Memory.

## Advisory IoC Reference


| Category | Item 1 | Item 2 | Item 3 | Item 4 |
|---|---|---|---|---|
| CVE | CVE-2026-24060 | CVSS v3.1 9.1 Critical | WebCTRL Premium Server \< v8.5 | Cleartext BACnet transmission enables passive credential/command interception |
| CVE | CVE-2026-32666 | CVSS v3.1 7.5 High | WebCTRL Premium Server \< v8.5 | BACnet authentication bypass via device/source spoofing |
| CVE | CVE-2026-25086 | CVSS v3.1 7.7 High | WebCTRL Premium Server \< v8.5 | Port-binding race condition enables BACnet service impersonation |
| Threat Actor | None attributed at this time |  |  |  |
| Malware | None attributed |  |  |  |
| Network IOC | None published — monitor CISA ICS feeds and vendor advisories |  |  |  |
| File IOC | None published — monitor NVD and Automated Logic vendor feeds |  |  |  |
| Behavioral | BACnet WriteProperty from non-authorized source IP |  | UDP/47808 | Potential CVE-2026-32666 exploitation — unauthenticated write to BACnet object |
| Behavioral | Who-Is broadcast flood \>50 requests per 10 seconds from non-controller host |  | UDP/47808 | Reconnaissance precursor to CVE-2026-32666 spoofing |
| Behavioral | Multiple processes simultaneously bound to UDP port 47808 on WebCTRL host |  |  | CVE-2026-25086 — port-binding race condition for service impersonation |
| Behavioral | Packet capture tool (Wireshark/tcpdump/tshark) executed on WebCTRL host outside maintenance window |  |  | CVE-2026-24060 — passive interception of cleartext BACnet traffic |
| Behavioral | New Windows service registered on WebCTRL host outside approved change window |  |  | CVE-2026-25086 — attacker-controlled service bound to BACnet port |
| Behavioral | PCAP file (.pcap/.pcapng) created on WebCTRL host or adjacent IT/OT bridging host |  |  | CVE-2026-24060 — evidence of cleartext credential/command capture |
