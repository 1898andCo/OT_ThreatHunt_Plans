# Threat Hunt Plan: Silex SD-330AC and AMC Manager Exploitation (CVE-2026-32955, CVE-2026-32956, CVE-2026-32958, CVE-2026-32960, CVE-2026-32964, CVE-2026-32965)

Date: 2026-04-22 \| Revision: 1.0
# Hunt Objective and Scope

The objective of this hunt is to identify exploitation, pre-exploitation reconnaissance, and post-exploitation pivot activity targeting Silex Technology SD-330AC 802.11 a/b/g/n/ac wireless serial device servers running firmware version 1.42 and earlier, and the companion AMC Manager administration software at version 5.0.2 and earlier. The hunt assumes that affected devices may be reachable either directly from the internet, via a trusted partner or vendor remote-support path, or from within an OT or healthcare VLAN to which an adversary has already established initial access.

***Environmental scope covers OT network segments and healthcare biomedical VLANs where SD-330AC is deployed as a wireless serial bridge, administrative jump hosts and AMC Manager servers used to manage the fleet, SPAN or TAP feeds on the wireless-edge and OT-edge aggregation layers, firewall and NGFW management-plane logs, NetFlow collectors, and any cloud-forwarded syslog or web-access logs that observe management traffic toward these devices. Because the SD-330AC itself does not host conventional EDR agents, hunt queries against CrowdStrike Falcon and Datadog Live Process Monitoring target adjacent Windows and Linux hosts — engineering workstations, historian and SCADA servers, admin jump boxes, and AMC Manager servers — that interact with the converter on the management plane.***

Time window: the default hunt horizon is the prior 30 days from execution, extended to 90 days in environments where Forescout or the organization's own scanning has identified a public-internet-exposed SD-330AC. Escalate to a full incident-response investigation if any exploitation indicator fires.

# Hypotheses and Hunt Procedures

## Hypothesis 1

A remote unauthenticated attacker has exploited CVE-2026-32956 against the SD-330AC or AMC Manager login redirect URL handler to trigger a heap-based buffer overflow and achieve remote code execution, observable as HTTP POST requests to the login endpoint with oversized redirect parameters, anomalous outbound connections from the SD-330AC management IP toward internet or internal hosts on non-standard ports, and web-server log entries showing crash signatures or 500-class responses immediately followed by new east-west connections.

### MITRE ATT&CK

Initial Access \| T1190 — Exploit Public-Facing Application \| Direct exploitation of the SD-330AC web management interface to gain execution on the device.

### MITRE ATT&CK

Execution \| T1059 — Command and Scripting Interpreter \| Injected shellcode runs with the privileges of the web-management service on the converter.

### Collection Queries

CrowdStrike Falcon FQL — inventory monitoring and jump hosts whose processes have communicated with SD-330AC converter IPs so downstream joins have process context:

```text
#event_simpleName = "NetworkConnectIP4"

| RemotePort = "80" OR RemotePort = "443" OR RemotePort = "8443"

| cidr(RemoteAddressIP4, subnet=["<silex_subnet_1>", "<silex_subnet_2>"])

| join(query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)}, field=[aid,RawProcessId], include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName])

| table([ComputerName, FileName, RemoteAddressIP4, RemotePort, CommandLine, ParentBaseFileName])

```
CrowdStrike Falcon FQL — hunt web-client processes on admin hosts invoking long redirect URLs against Silex targets:

```text
#event_simpleName = "ProcessRollup2"

| FileName = /^(curl\\exe|wget\\exe|python\\exe|python3\\exe|powershell\\exe|pwsh\\exe)\$/i

| CommandLine = /redirect=[A-Za-z0-9%._-]{200,}/i

| table([ComputerName, AuthenticationId, UserName, ImageFileName, FileName, CommandLine, ParentBaseFileName])

```
BPF packet capture on the wireless-edge SPAN feed — isolate SD-330AC management plane into a rolling 24-hour capture set:

```bash
tcpdump -i <span_iface> -G 3600 -W 24 -C 500 -w /var/pcap/silex-mgmt-%Y%m%d%H.pcap '(host <silex_ip_list>) and (tcp port 80 or tcp port 443 or tcp port 8443)'

```
BPF packet capture — rate-limited capture of long-POST bodies for offline analysis:

```bash
tcpdump -i <span_iface> -G 3600 -W 24 -s 0 -w /var/pcap/silex-body-%Y%m%d%H.pcap 'tcp dst port 80 and dst host <silex_ip_list> and tcp[tcpflags] & tcp-push != 0'

```
Datadog Log Search — surface long redirect parameter activity from forwarded NGFW/WAF logs:

```text
source:paloalto @dest.ip:(<silex_subnet_1> OR <silex_subnet_2>) @url.path:\*login\* @payload:\*redirect=\*

// time range: now - 30d to now; Analytics Table view; group by @network.client.ip

```
Datadog Log Search — fallback visibility where Live Process Monitoring is not enabled:

```text
source:windows (message:"redirect=" OR message:"SD-330AC" OR message:"AMC Manager") @network.client.ip:(<silex_subnet_1> OR <silex_subnet_2>)

// time range: now - 30d to now; Analytics Table view; group by @usr.name

```
Datadog Live Process Monitoring (Infrastructure \> Processes) — admin-host curl/wget/python with long redirect parameters:

command:curl user:\* OR command:python user:\*

```text
// Free-text filter: redirect= OR SD-330AC OR login-redirect

```
Datadog source:cloudtrail — surface unexpected AWS API activity from paths that could indicate AMC Manager hosted in cloud being abused:

```text
source:cloudtrail @evt.name:(AssumeRole OR GetSessionToken) -@network.client.ip:10.\* -@network.client.ip:172.16.\* -@network.client.ip:192.168.\*

// time range: now - 30d to now

```
Windows Event IDs to collect on admin/AMC Manager hosts — forward via WEF or use Get-WinEvent:

\- 4688 (Process Creation) — capture curl/python/PowerShell launches

\- 4624 (Logon Success) — admin-host interactive and network logons

\- 4104 (PowerShell ScriptBlock) — PowerShell sessions touching SD-330AC IPs

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-30)} | Where-Object { \$_.Message -match '(curl|wget|python|Invoke-WebRequest|Invoke-RestMethod)' -and \$_.Message -match 'redirect=' } | Export-Csv -Path C:\hunt\silex-h1-proc.csv -NoTypeInformation

```
OT Data Collection: Claroty CTD — Administration \> Reports \> Connection Activity; filter Protocol = HTTP, HTTPS; Destination IP = Silex inventory; date range = 30 days; export CSV to C:\hunt\ctd-silex-conns.csv

OT Data Collection: Dragos Platform — Investigate \> Connection Timeline; filter Protocol = HTTP/HTTPS and Destination IP in Silex list; Detections panel filtered by Category = Initial Access

OT Data Collection: Nozomi Networks — Assets \> Connections; filter Protocol = HTTP/HTTPS; export via GET /api/open/connections?protocol=https&host=\<silex_ip\>

OT Data Collection: Armis — Asset Management \> Devices \> filter Manufacturer = Silex; export CSV; inspect Policy engine alerts referencing these devices over the hunt window

OT Data Collection: Tenable OT — Assets \> Devices \> Export; Events view for Event Type = Unauthorized Access targeting Silex asset IDs; REST API: GET /api/v1/assets and /api/v1/events

OT Data Collection: Forescout eyeInspect — Inventory \> Devices \> Export; GET /api/v1/connections; Threat Detection panel for HTTP anomaly alerts on Silex endpoints

SNMP polling — rolling switch-port and device-side counter collection:

```bash
snmpwalk -v2c -c <community> <switch_ip> IF-MIB::ifTable

snmpget -v2c -c <community> <switch_ip> IF-MIB::ifInOctets.<ifIndex> IF-MIB::ifOutOctets.<ifIndex> IF-MIB::ifInErrors.<ifIndex> IF-MIB::ifOutErrors.<ifIndex>

snmpwalk -v2c -c <community> <silex_ip> system

snmpwalk -v2c -c <community> <silex_ip> IF-MIB::ifTable

YARA file-system scan — stage on admin jump hosts, AMC Manager hosts, and forensic shares for exploit tooling or captured PCAPs containing exploit strings:

yara -r /opt/yara/rules/silex_bridgebreak.yar C:\users\\ C:\ProgramData\\ C:\hunt\\ >> C:\hunt\yara-silex-disk.txt

```
### Analysis Queries

CrowdStrike Falcon FQL — rate anomaly on admin-host web-client connections to SD-330AC IPs:

```text
#event_simpleName = "NetworkConnectIP4"

| cidr(RemoteAddressIP4, subnet=["<silex_subnet_1>", "<silex_subnet_2>"])

| top([ComputerName, RemoteAddressIP4, RemotePort], limit=50)

```
CrowdStrike Falcon FQL — rarity hunt (asc) for admin hosts that have never historically contacted SD-330AC IPs:

```text
#event_simpleName = "NetworkConnectIP4"

| cidr(RemoteAddressIP4, subnet=["<silex_subnet_1>", "<silex_subnet_2>"])

| groupBy([ComputerName, FileName], function=count(), limit=100000)

| sort(_count, order=asc, limit=50)

```
Wireshark display filter — POST body with oversized redirect parameter in captured PCAP:

http.request.method == "POST" and http.request.uri contains "login" and tcp.len \> 512

```bash
tshark -r silex-body-\*.pcap -Y 'http.request.method == "POST" and http.request.uri contains "login"' -T fields -e frame.time -e ip.src -e ip.dst -e http.content_length >> tshark-silex-longpost.txt

```
Wireshark display filter — outbound connections initiated by SD-330AC IP (post-exploitation egress):

ip.src == \<silex_ip\> and tcp.flags.syn == 1 and tcp.flags.ack == 0

```bash
tshark -r silex-mgmt-\*.pcap -Y 'ip.src in {<silex_ip_list>} and tcp.flags.syn == 1 and tcp.flags.ack == 0' -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport >> tshark-silex-egress.txt

```
Datadog Log Analytics — rate spikes in long redirect parameters hitting Silex targets:

```text
source:paloalto @dest.ip:(<silex_subnet_1> OR <silex_subnet_2>) @url.path:\*login\* @payload:\*redirect=\*

// Use Timeseries view; group by @network.client.ip; time range last 30 days; investigate any bucket with >5x median count

```
Datadog Audit Trail — admin-account changes coincident with exploit windows:

```text
source:datadog @evt.category:user_access @evt.name:login

// time range: now - 30d to now; group by @usr.name

```
Datadog Monitor (required):

```text
Type: Log Alert

Query: source:paloalto @dest.ip:(<silex_subnet_1> OR <silex_subnet_2>) @url.path:\*login\* @payload:\*redirect=\*[^&]{200\\,}\*

Evaluation window: last 5 minutes

Alert condition: count > 0

Message: "ALERT: BRIDGE:BREAK CVE-2026-32956 exploit pattern observed against Silex SD-330AC login redirect — immediate investigation required @pagerduty-soc"

```
Prerequisites: Palo Alto NGFW syslog forwarding to Datadog with URL filtering and body inspection enabled

Windows Event Log PowerShell analysis — correlate 4688 process creations on admin/AMC Manager hosts with Silex-directed connections:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-30)} | Where-Object { \$_.Message -match '(curl|wget|python|Invoke-WebRequest)' } | Select-Object TimeCreated,@{N='CmdLine';E={\$_.Properties[8].Value}},@{N='Account';E={\$_.Properties[1].Value}} | Export-Csv -Path C:\hunt\silex-h1-ps.csv -NoTypeInformation

```
OT Protocol Analysis — check Claroty/Dragos/Nozomi for serial-side anomalies originating from SD-330AC IP within 5 minutes of any suspected exploitation event; flag any new connection pair, new protocol, or baseline deviation

```text
YARA memory scan — scan curl/wget/python processes on admin hosts for in-memory exploit URL fragments or reverse-shell staging:

PowerShell: Get-Process curl,wget,python,pwsh -ErrorAction SilentlyContinue | ForEach-Object { yara -p \$_.Id C:\hunt\rules\silex_bridgebreak.yar >> C:\hunt\yara-silex-mem.txt }

```
Remote at scale via CrowdStrike RTR: execute a custom script that invokes YARA -p across candidate PIDs; results returned to RTR session

## Hypothesis 2

An attacker has bypassed authentication on an SD-330AC through the retained-credential reuse flaw (CVE-2026-32960) or has claimed administrative ownership of a factory-default unit with no enforced administrator password (CVE-2026-32965), observable as successful login events from unexpected source IPs, sudden changes to the administrator password from non-admin subnets, and new configuration-change events in AMC Manager attributable to accounts whose credentials have not been validated through change management.

### MITRE ATT&CK

Initial Access \| T1078 — Valid Accounts \| Reuse of retained admin credentials impersonates a legitimate user on the SD-330AC.

### MITRE ATT&CK

Defense Evasion \| T1078.001 — Default Accounts \| Takeover of a factory-default SD-330AC by setting the first administrative password.

### Collection Queries

Datadog Log Search — capture NGFW/WAF HTTP logs for successful admin logons to Silex management IPs from non-admin source ranges:

```text
source:paloalto @dest.ip:(<silex_subnet_1> OR <silex_subnet_2>) @status:200 @url.path:(\*login\* OR \*admin\* OR \*password\*) -@network.client.ip:<admin_subnet>

// time range: now - 30d to now; Analytics Top List view; group by @network.client.ip

```
Datadog Log Search — surface AMC Manager audit-log entries for password changes and new-user creation (where AMC Manager forwards syslog):

```text
source:syslog @host.ip:(<amc_manager_subnet>) (message:"password changed" OR message:"user created" OR message:"admin reset")

// time range: now - 30d to now

```
Datadog Live Process Monitoring — admin-host processes executing Silex CLI or API clients outside maintenance windows:

command:silex user:\* OR command:amcmanager user:\* OR command:python user:\*

```text
// Free-text filter: set-password OR admin-reset OR factory-default

```
BPF capture — capture Silex authentication traffic:

```bash
tcpdump -i <span_iface> -G 3600 -W 48 -C 500 -w /var/pcap/silex-auth-%Y%m%d%H.pcap 'tcp and (tcp port 80 or tcp port 443 or tcp port 8443) and (host <silex_ip_list>)'

```
Windows Event IDs to collect:

\- 4688 (Process Creation) with commands invoking AMC Manager CLI

\- 4104 (PowerShell ScriptBlock) invocations touching Silex management endpoints

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=(Get-Date).AddDays(-30)} | Where-Object { \$_.Message -match '(SD-330AC|AMC Manager|set-password|factory-default)' } | Export-Csv -Path C:\hunt\silex-h2-ps.csv -NoTypeInformation

```
CrowdStrike Falcon FQL — admin-host processes invoking password-change commands against Silex devices:

```text
#event_simpleName = "ProcessRollup2"

| CommandLine = /(SD-?330AC|AMC.\*Manager|set-?password|factory-?default|admin-?reset)/i

| table([ComputerName, AuthenticationId, UserName, FileName, CommandLine, ParentBaseFileName])

```
OT Data Collection: Claroty CTD — Administration \> Reports \> Connection Activity; filter Protocol = HTTP/HTTPS and Destination IP = Silex inventory; inspect packet-level for authentication headers

OT Data Collection: Dragos Platform — Detections panel for HTTP anomaly alerts on Silex endpoints; Investigate \> Connection Timeline for source IP analysis

OT Data Collection: Nozomi Networks — Assets \> Connections; export via GET /api/open/connections?destination_ip=\<silex_ip\>&protocol=http

OT Data Collection: Armis — Policy engine: add "Admin access to Silex SD-330AC from non-admin-subnet source" and review violations

OT Data Collection: Tenable OT — Events view; filter Event Type = Unauthorized Access; destination asset = Silex inventory IDs

OT Data Collection: Forescout eyeInspect — Threat Detection panel; inspect HTTP anomaly alerts on Silex endpoints

### Analysis Queries

Datadog Log Analytics — identify source IPs outside the admin allowlist that successfully authenticated to SD-330AC:

```text
source:paloalto @dest.ip:(<silex_subnet_1> OR <silex_subnet_2>) @status:200 @url.path:\*login\* -@network.client.ip:<admin_subnet>

// Use Table view; group by @network.client.ip, @usr.name; time range last 30 days

```
Datadog Audit Trail — correlate with any Datadog admin-account changes in the same window:

```text
source:datadog @evt.category:user_management @evt.name:(role_change OR user_created OR password_change)

// time range: now - 30d to now

```
Datadog Monitor (required):

```text
Type: Log Alert

Query: source:paloalto @dest.ip:(<silex_subnet_1> OR <silex_subnet_2>) @status:200 @url.path:\*login\* -@network.client.ip:<admin_subnet>

Evaluation window: last 10 minutes

Alert condition: count > 0

Message: "ALERT: Successful admin login to Silex SD-330AC from non-admin source IP — verify against active engagements @pagerduty-soc"

```
Prerequisites: NGFW logs with URL filtering visibility forwarded to Datadog; admin-subnet tag maintained

Wireshark display filter — inspect authentication headers and cookies reaching Silex IPs:

http.cookie or http.authorization and ip.dst in {\<silex_ip_list\>}

```bash
tshark -r silex-auth-\*.pcap -Y 'http.authorization or http.cookie' -T fields -e frame.time -e ip.src -e ip.dst -e http.authorization -e http.cookie >> tshark-silex-auth.txt

```
OT Protocol Analysis — SNMP polling of SD-330AC system OIDs for sysContact/sysLocation/sysName changes (attacker ownership markers):

while true; do for ip in \<silex_ip_list\>; do snmpwalk -v2c -c \<community\> \$ip system \| grep -E "sysName\|sysContact\|sysLocation" \| tee -a /var/log/silex-system-\$(date +%F).log; done; sleep 300; done

```text
YARA memory scan — on admin hosts for in-memory strings that indicate active auth-bypass tooling:

Get-Process curl,wget,python,pwsh -ErrorAction SilentlyContinue | ForEach-Object { yara -p \$_.Id C:\hunt\rules\silex_bridgebreak.yar >> C:\hunt\yara-silex-h2-mem.txt }

```
## Hypothesis 3

An attacker has leveraged the SD-330AC and AMC Manager hard-coded firmware signing key (CVE-2026-32958) to apply a tampered firmware image, observable as unexpected firmware-update events in SD-330AC or AMC Manager logs, altered device fingerprints in OT asset management platforms, and SNMP sysUpTime resets inconsistent with scheduled maintenance.

### MITRE ATT&CK

Persistence \| T1542 — Pre-OS Boot \| Malicious firmware replaces vendor firmware to establish persistence below the OS.

### MITRE ATT&CK

Impair Defenses \| T1554 — Compromise Client Software Binary \| Firmware tampering compromises the integrity of the operational binary.

### Collection Queries

SNMP polling — rolling sysUpTime/sysDescr collection every 5 minutes for all SD-330AC assets:

while true; do for ip in \<silex_ip_list\>; do snmpwalk -v2c -c \<community\> \$ip system \| tee -a /var/log/silex-uptime-\$(date +%F).log; done; sleep 300; done

Datadog Log Search — firmware-update and reboot indicators from forwarded syslog:

```text
source:syslog (message:"firmware" OR message:"reboot" OR message:"coldStart" OR message:"warmStart" OR message:"update applied") @host.ip:(<silex_ip_list>)

// time range: now - 90d to now; Analytics Table view; group by @host.ip

```
BPF capture — firmware transfer HTTP(S) activity toward Silex converters:

```bash
tcpdump -i <span_iface> -G 3600 -W 48 -C 500 -w /var/pcap/silex-fw-%Y%m%d%H.pcap 'host <silex_ip_list> and (tcp port 80 or tcp port 443 or tcp port 8443)'

```
OT Data Collection: Claroty CTD — Baselines \> Asset Fingerprints; flag any SD-330AC showing a new firmware version outside the planned deployment window

OT Data Collection: Dragos Platform — Detections panel filtered by Category = Firmware Change; review associated connection timeline

OT Data Collection: Nozomi Networks — Assets \> Devices \> inspect Firmware Version column and deltas; GET /api/open/assets for programmatic diff

OT Data Collection: Armis — Device Timeline per Silex asset; inspect firmware-change events

OT Data Collection: Tenable OT — Events view; Event Type = Firmware Change Detected; correlate with IP and timestamp

OT Data Collection: Forescout eyeInspect — Inventory diff report comparing asset fingerprints across consecutive weekly snapshots

```text
YARA file-system scan — scan forensic image or staged firmware directory for tampered SD-330AC firmware markers:

yara -r /opt/yara/rules/silex_tampered_fw.yar /mnt/forensic/ /var/firmware-staging/ >> /var/log/yara-silex-fw.txt

```
Windows Event IDs to collect — on admin/AMC Manager host that might have initiated the firmware update:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddDays(-30)} | Where-Object { \$_.Message -match '(AMCManager|silex|firmware|\\bin|\\img|\\rom)' } | Export-Csv -Path C:\hunt\silex-h3-fwadmin.csv -NoTypeInformation

```
CrowdStrike Falcon FQL — monitoring/AMC Manager hosts that wrote firmware images to disk:

```text
#event_simpleName = "NewExecutableWritten"

| TargetFileName = /silex|sd-?330|firmware.\*\\(bin|img|rom)\$/i

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

Message: "ALERT: Firmware or reboot event on Silex SD-330AC outside change window — potential CVE-2026-32958 firmware tampering @pagerduty-soc"

```
Prerequisites: Syslog from Silex converters and/or OT monitoring platform forwarded to Datadog; maintenance-window schedule documented in monitor tags

Wireshark display filter — firmware POST to SD-330AC web interface:

http.request.method == "POST" and (http.request.uri contains "firmware" or http.request.uri contains "upload") and ip.dst in {\<silex_ip_list\>}

```bash
tshark -r silex-fw-\*.pcap -Y 'http.request.method == "POST" and http.request.uri contains "firmware"' -T fields -e frame.time -e ip.src -e ip.dst -e http.content_length >> tshark-silex-fwpost.txt

```
OT Protocol Analysis — compare current SD-330AC firmware hashes to known-good vendor firmware 1.50 hashes via OT platform APIs (Claroty, Nozomi, Forescout); any mismatch is automatic escalation

```text
YARA memory scan — on any Windows AMC Manager host suspected to have pushed firmware:

Get-Process | Where-Object { \$_.ProcessName -match 'AMCManager|curl|wget|python' } | ForEach-Object { yara -p \$_.Id C:\hunt\rules\silex_tampered_fw.yar >> C:\hunt\yara-silex-fw-mem.txt }

```
## Hypothesis 4

An attacker with control of a compromised SD-330AC has pivoted onto the OT or healthcare network, observable as unusual east-west traffic originating from the SD-330AC management IP toward PLCs, medical instruments, historians, or engineering workstations, and as anomalous serial command sequences on the downstream serial side that diverge from historian baselines.

### MITRE ATT&CK

Lateral Movement \| T1210 — Exploitation of Remote Services \| Use of the compromised converter as a pivot to reach downstream OT or medical endpoints.

### MITRE ATT&CK

Impact \| T0831 — Manipulation of Control (ICS) \| Injection or alteration of serial commands reaching PLCs or instruments with operational consequence.

### Collection Queries

BPF capture — east-west from SD-330AC IP into OT/medical device VLANs:

```bash
tcpdump -i <ot_span_iface> -G 3600 -W 48 -C 500 -w /var/pcap/silex-eastwest-%Y%m%d%H.pcap 'src host <silex_ip> and not (dst host <admin_jump_host_list>)'

```
Datadog Log Search — flow records showing SD-330AC-originated east-west traffic:

```text
source:netflow @network.source.ip:(<silex_subnet_1> OR <silex_subnet_2>) -@network.destination.ip:(<admin_jump_subnet>)

// time range: now - 30d to now; Analytics Table view; group by @network.destination.ip, @network.destination.port

```
Datadog Live Process Monitoring — admin-host sessions with Modbus, CIP, or OPC-UA client tooling initiated around SD-330AC pivot windows:

command:modbus-cli user:\* OR command:opcua user:\* OR command:ethernetip user:\*

CrowdStrike Falcon FQL — engineering workstations that received connections from SD-330AC IP (reverse hunt):

```text
#event_simpleName = "NetworkReceiveAcceptIP4"

| cidr(RemoteAddressIP4, subnet=["<silex_subnet_1>", "<silex_subnet_2>"])

| join(query={#event_simpleName=ProcessRollup2 | groupBy([aid,RawProcessId], function=selectLast([ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName]), limit=100000)}, field=[aid,RawProcessId], include=[ImageFileName,FileName,CommandLine,AuthenticationId,ParentBaseFileName])

| table([ComputerName, FileName, RemoteAddressIP4, LocalPort, CommandLine, ParentBaseFileName])

```
OT Data Collection: Claroty CTD — Baselines \> Communication Patterns; flag any new connection pair involving Silex IPs

OT Data Collection: Dragos Platform — Detections panel filtered by Category = Lateral Movement or Discovery with source IP = Silex inventory

OT Data Collection: Nozomi Networks — Assets \> Connections; GET /api/open/connections?source_ip=\<silex_ip\>; diff against 30-day baseline

OT Data Collection: Armis — Policy engine: pre-create a policy "New east-west flow from Silex SD-330AC" and review violations

OT Data Collection: Tenable OT — Network Map; identify new edges originating from Silex assets in the prior 30 days

OT Data Collection: Forescout eyeInspect — Connections view; filter Source = Silex asset; export deltas from baseline

Historian/SCADA alarm correlation — pull OSI PI, GE Proficy, or AVEVA System Platform audit trails for operator-initiated commands and sensor-value edits occurring within five minutes of any SD-330AC east-west event

Windows Event IDs to collect — on engineering workstations and historian/SCADA servers:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=5156; StartTime=(Get-Date).AddDays(-30)} | Where-Object { \$_.Message -match '<silex_ip_pattern>' } | Export-Csv -Path C:\hunt\silex-h4-wfp.csv -NoTypeInformation

```
SNMP polling — hunt for interface error/utilization spikes on switch ports facing OT/medical endpoints downstream of the SD-330AC:

```bash
snmpwalk -v2c -c <community> <ot_switch_ip> IF-MIB::ifTable

snmpget -v2c -c <community> <ot_switch_ip> IF-MIB::ifInOctets.<plc_port> IF-MIB::ifInErrors.<plc_port>

```
### Analysis Queries

Wireshark display filter — EtherNet/IP CIP service code analysis from SD-330AC:

cip and ip.src == \<silex_ip\>

```bash
tshark -r silex-eastwest-\*.pcap -Y 'cip and ip.src == <silex_ip>' -T fields -e frame.time -e ip.src -e ip.dst -e cip.service >> tshark-silex-cip.txt

```
Wireshark display filter — Modbus function-code review:

modbus and ip.src == \<silex_ip\>

```bash
tshark -r silex-eastwest-\*.pcap -Y 'modbus and ip.src == <silex_ip>' -T fields -e frame.time -e mbtcp.trans_id -e modbus.func_code >> tshark-silex-modbus.txt

```
Datadog Log Analytics — flow deltas:

```text
source:netflow @network.source.ip:(<silex_subnet_1> OR <silex_subnet_2>)

// Use Top List view; group by @network.destination.ip; compare against previous 30-day period; any new destination is suspect

```
Datadog Monitor (required):

```text
Type: Log Alert

Query: source:netflow @network.source.ip:(<silex_subnet_1> OR <silex_subnet_2>) -@network.destination.ip:(<baseline_destination_subnet>)

Evaluation window: last 5 minutes

Alert condition: count > 0

Message: "ALERT: New east-west flow from Silex SD-330AC — validate against baseline @pagerduty-soc"

```
Prerequisites: NetFlow/VPC flow logs from OT-edge switches forwarded to Datadog; baseline destination subnet tag maintained

CrowdStrike Falcon FQL — unexpected process on engineering workstation coincident with SD-330AC-originated connection:

```text
#event_simpleName = "ProcessRollup2"

| FileName = /^(rslogix5000\\exe|studio5000\\exe|logixdesigner\\exe|opc.\*\\exe)\$/i

| table([ComputerName, AuthenticationId, UserName, ImageFileName, FileName, CommandLine, ParentBaseFileName])

```
Historian baseline deviation — pull tag-level statistics (mean, stddev) for critical setpoints over the 30-day prior period; flag any reading more than 3 sigma from baseline coinciding with an SD-330AC east-west event

OT Protocol Analysis — Claroty/Dragos/Nozomi baseline-deviation reports: any new CIP service code, Modbus function code, or OPC-UA method invocation originating from SD-330AC IP in the prior 30 days

```text
YARA memory scan — on engineering workstations and historian servers that received connections from the SD-330AC:

Get-Process | Where-Object { \$_.ProcessName -match 'rslogix|studio5000|opc|historian|pi.\*' } | ForEach-Object { yara -p \$_.Id C:\hunt\rules\silex_bridgebreak.yar >> C:\hunt\yara-silex-h4-mem.txt }

```
# Threat Actor Profile

Opportunistic mass-scanning actors are the highest-probability first exploiters. Nuclei templates, Greynoise honeypot observations, and custom Python scripts will be updated to fingerprint SD-330AC management banners and probe the pre-authentication heap overflow within days of a public proof-of-concept; attribution is likely to remain unclear and activity will present as generic botnet or crypto-mining enrollment.

Nation-state OT-focused actors (Volt Typhoon, Sandworm, Lazarus DPRK sub-clusters, Iranian OilRig and APT33 contractors) have historically targeted edge appliances as staging positions into critical-infrastructure OT networks. Their tradecraft against SD-330AC would be characterized by low-and-slow reconnaissance, use of the retained-credential reuse primitive to impersonate legitimate admin traffic, selective firmware tampering rather than noisy payloads, and longer dwell time focused on serial-side command manipulation rather than immediate disruption.

Ransomware affiliates and initial-access brokers are the middle tier. They will weaponize the pre-authentication heap overflow for initial foothold into industrial networks whose IT/OT boundary protections have degraded, then sell access to ransomware operators or OT-targeting actors. Insider abuse by OEM or integrator staff with over-broad remote access to SD-330AC deployments is lower-probability but credible, particularly in healthcare and facilities environments where the converters are commonly commissioned by third parties.

# Data Sources Required

***Network:*** firewall and NGFW logs (Palo Alto, Fortinet, Check Point), NGFW URL-filtering records, NetFlow/sFlow from OT-edge and wireless-edge aggregation, SPAN/TAP feeds into standalone IDS/IDPS (Snort, Suricata, Zeek), packet captures from rolling tcpdump, VPN gateway logs, wireless controller logs where SD-330AC is attached.

***Endpoint:*** CrowdStrike Falcon from engineering workstations, historian/SCADA servers, admin jump hosts, and AMC Manager servers; Windows Event Logs (Security, System, PowerShell/Operational, WFP); Sysmon from high-value admin hosts; Datadog Agent with Live Process Monitoring on Linux administrative and monitoring appliances.

***OT/ICS:*** historian alarm and audit logs (OSI PI, AVEVA System Platform, GE Proficy), SCADA console logs, PLC logs where supported, OT monitoring platform exports from Claroty CTD, Dragos Platform, Nozomi Networks, Armis, Tenable OT, and Forescout eyeInspect.

***Vendor/device:*** SD-330AC and AMC Manager syslog forwarding, SNMP polling results from the converters themselves and from the switches carrying their traffic, SNMP trap receiver logs for coldStart/warmStart/linkDown/linkUp events, wireless SSID-association and deauthentication logs on the controllers bridging SD-330AC wireless access.

# Detection Signatures

#### SIGMA Rule 1 — proxy category: Long redirect URL POST targeting SD-330AC or AMC Manager (CVE-2026-32956 heap overflow probe)

```yaml
title: BRIDGE:BREAK Silex SD-330AC Redirect URL Overflow Probe

id: 8b2f4c31-7e1d-49ab-bc60-3d9e4f8a1b72

status: experimental

description: Detects HTTP POST requests to Silex SD-330AC or AMC Manager login endpoints containing oversized redirect parameters consistent with the CVE-2026-32956 heap-based buffer overflow.

references:

```
\- https://nvd.nist.gov/vuln/detail/CVE-2026-32956

\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10

```yaml
author: 1898 & Co. Threat Hunt

date: 2026-04-22

tags:

```
\- attack.initial_access

\- attack.t1190

\- cve.2026.32956

```yaml
logsource:

```
category: proxy

product: paloalto

```yaml
detection:

```
selection_dest:

dst_ip\|contains:

\- '\<silex_subnet_1\>'

\- '\<silex_subnet_2\>'

selection_uri:

cs-uri-stem\|contains: 'login'

selection_body:

cs-uri-query\|re: 'redirect=\[A-Za-z0-9%.\_-\]{200,}'

```yaml
condition: selection_dest and selection_uri and selection_body

falsepositives:

```
\- Legitimate browser-driven redirect URLs from administrative portals in rare long-token SSO flows

```yaml
level: high

```
#### SIGMA Rule 2 — network_connection category: Unexpected egress from SD-330AC IP to non-admin destinations

```yaml
title: BRIDGE:BREAK Silex SD-330AC Unexpected Egress

id: 1c3e5f29-6b74-4a88-9d0c-2b4f6a8e1d32

status: experimental

description: Detects SYN-only outbound connections originating from Silex SD-330AC IP ranges to destinations outside the documented admin subnet, consistent with post-exploitation egress under CVE-2026-32956 or CVE-2026-32958.

references:

```
\- https://nvd.nist.gov/vuln/detail/CVE-2026-32956

\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10

```yaml
author: 1898 & Co. Threat Hunt

date: 2026-04-22

tags:

```
\- attack.command_and_control

\- attack.t1071

\- cve.2026.32956

```yaml
logsource:

```
category: network_connection

product: zeek

```yaml
detection:

selection:

```
src_ip\|contains:

\- '\<silex_subnet_1\>'

\- '\<silex_subnet_2\>'

filter_admin:

dst_ip\|contains: '\<admin_subnet\>'

```yaml
condition: selection and not filter_admin

falsepositives:

```
\- NTP, SNMP polling, and configured syslog forwarding from SD-330AC to approved collectors

```yaml
level: high

```
#### SIGMA Rule 3 — process_creation category: Admin-host curl/python invocation with Silex exploit fragments

```yaml
title: BRIDGE:BREAK Admin Host Silex Exploit Client Invocation

id: 2d4f6a38-8c19-4b27-ae5d-3f6a9b2c1e48

status: experimental

description: Detects curl, wget, python, or PowerShell Invoke-WebRequest invocations on admin, AMC Manager, or engineering hosts whose command line matches Silex SD-330AC exploit fragments (long redirect parameter, set-password, factory-default reset).

references:

```
\- https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10

\- https://nvd.nist.gov/vuln/detail/CVE-2026-32956

\- https://nvd.nist.gov/vuln/detail/CVE-2026-32960

\- https://nvd.nist.gov/vuln/detail/CVE-2026-32965

```yaml
author: 1898 & Co. Threat Hunt

date: 2026-04-22

tags:

```
\- attack.initial_access

\- attack.t1190

\- attack.execution

\- attack.t1059

```yaml
logsource:

```
category: process_creation

product: windows

```yaml
detection:

```
selection_img:

Image\|endswith:

\- '\curl.exe'

\- '\wget.exe'

\- '\python.exe'

\- '\python3.exe'

\- '\powershell.exe'

\- '\pwsh.exe'

selection_cmd:

CommandLine\|re: '(SD-?330AC\|redirect=\[^& \]{200,}\|set-?password\|factory-?default\|admin-?reset)'

```yaml
condition: selection_img and selection_cmd

falsepositives:

```
\- Red-team or penetration-test engagements targeting SD-330AC with documented scope

\- Legitimate AMC Manager CLI automation during documented change windows

```yaml
level: high

```
#### Snort/Suricata Rule 1 — HTTP POST to SD-330AC login with oversized redirect parameter (CVE-2026-32956)

```text
alert http any any -> <silex_ip_list> any (msg:"BRIDGE:BREAK Silex SD-330AC Redirect URL Overflow Attempt"; flow:to_server,established; http.uri; content:"login"; nocase; http.request_body; pcre:"/redirect=[A-Za-z0-9%._-]{200,}/i"; threshold: type limit, track by_src, count 1, seconds 60; classtype:attempted-admin; reference:cve,2026-32956; reference:url,nvd.nist.gov/vuln/detail/CVE-2026-32956; sid:100026010; rev:1; metadata:campaign BridgeBreak, product Silex SD-330AC;)

```
#### Snort/Suricata Rule 2 — HTTP successful 200 response to Silex login from non-admin source (auth-bypass / null-password takeover)

```text
alert http any any -> <silex_ip_list> any (msg:"BRIDGE:BREAK Silex SD-330AC Successful Auth From Unexpected Source"; flow:to_server,established; http.uri; pcre:"/(login|admin|password|factory)/i"; threshold: type both, track by_src, count 1, seconds 300; classtype:attempted-admin; reference:cve,2026-32960; reference:cve,2026-32965; reference:url,nvd.nist.gov/vuln/detail/CVE-2026-32960; sid:100026011; rev:1; metadata:campaign BridgeBreak, product Silex SD-330AC, note "pair with ingress ACL to exclude admin_subnet";)

```
***YARA Rule 1 (disk artifacts) — Silex_BridgeBreak_Exploit_OnDisk: this rule targets staged exploit payloads, PCAP captures, and scripts on analyst or admin hosts that contain SD-330AC-specific exploit URL fragments and oversized redirect parameter patterns. The condition is structured as any-of so a single unambiguous indicator yields a hit, while the anchored regex for the long redirect parameter minimizes false positives against general-purpose HTTP fuzzing corpora. Run with yara -r across admin host user directories, forensic mount points, and PCAP staging directories.***

```yara
rule Silex_BridgeBreak_Exploit_OnDisk

{

```
meta:

description = "Detects on-disk Silex SD-330AC BRIDGE:BREAK exploit fragments (long redirect URL and admin-reset markers)"

author = "1898 & Co. Threat Hunt"

date = "2026-04-22"

reference = "https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10"

strings:

\$s_silex_redirect = /redirect=\[A-Za-z0-9%.\_-\]{200,}/ ascii

\$s_silex_login = "/login" ascii wide

\$s_silex_product = "SD-330AC" ascii wide

\$s_silex_amc = "AMCManager" ascii wide

\$s_factory_reset = /factory-?default\|admin-?reset\|set-?password/ ascii

\$s_auth_pass_header = /Authorization:\s\*Basic\s+\[A-Za-z0-9+\\=\]+/ ascii

condition:

any of them

```text
}

```
***YARA Rule 2 (process memory) — Silex_BridgeBreak_Inflight_Memory: this rule scans live process memory on admin hosts, AMC Manager servers, and Linux monitoring appliances for in-flight SD-330AC exploit strings that would only appear transiently during active exploitation. The condition requires either a Silex-specific long-redirect probe, or the product identifier combined with a factory-reset or set-password fragment, reducing false positives against documentation or training material resident in memory. Analysts should invoke via yara -p against curl, wget, python, PowerShell, and AMC Manager processes, or use CrowdStrike Real Time Response to execute across the admin host population.***

```yara
rule Silex_BridgeBreak_Inflight_Memory

{

```
meta:

description = "Detects in-memory Silex BRIDGE:BREAK exploit strings in live processes (transient active-exploitation indicators)"

author = "1898 & Co. Threat Hunt"

date = "2026-04-22"

reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32956"

strings:

\$m_silex_redirect = /redirect=\[A-Za-z0-9%.\_-\]{200,}/ ascii

\$m_silex_product = "SD-330AC" ascii wide

\$m_silex_amc = "AMCManager" ascii wide

\$m_factory_reset = /factory-?default\|admin-?reset\|set-?password/ ascii

\$m_shell_seed = /(\\bin\\(sh\|bash)\|nc\s+-e\|\\dev\\tcp\\)/ ascii

condition:

\$m_silex_redirect or

( any of (\$m_silex_product, \$m_silex_amc) and any of (\$m_factory_reset, \$m_shell_seed) )

```text
}

```
***YARA Rule 3 (firmware integrity) — Silex_Tampered_Firmware_Image: this rule inspects SD-330AC firmware images staged on AMC Manager hosts or captured in forensic images for markers associated with tampered firmware produced under CVE-2026-32958, specifically the presence of embedded shell-dropper strings adjacent to legitimate Silex header markers. The condition requires at least one Silex header string AND two or more payload markers, which reliably excludes legitimate vendor images since unmodified images never contain dropper or persistence fragments. Pair with vendor signing-key verification: a hit on this rule combined with a failed signature check is automatic escalation under Section 8 criterion 7.***

```yara
rule Silex_Tampered_Firmware_Image

{

```
meta:

description = "Detects markers of tampered Silex SD-330AC firmware images (CVE-2026-32958 abuse)"

author = "1898 & Co. Threat Hunt"

date = "2026-04-22"

reference = "https://nvd.nist.gov/vuln/detail/CVE-2026-32958"

strings:

\$h_silex_hdr = "SD-330AC" ascii wide

\$h_silex_amc = "AMCManager" ascii wide

\$p_shell = "/bin/sh" ascii

\$p_dropper = /(wget\|curl\|tftp)\s+-\[a-zA-Z\]?\s\*\[a-zA-Z0-9:\\.\]+/ ascii

\$p_persist = /(rc\\local\|init\\d\|cron\|inittab)/ ascii

\$p_revsh = /(\\dev\\tcp\\\|nc\s+-e\|socat\s+exec:)/ ascii

condition:

any of (\$h_silex\_\*) and 2 of (\$p\_\*)

```text
}

```
# Indicators of Compromise

Network IOCs (behavioral): HTTP POST requests to SD-330AC login endpoints containing redirect= parameters exceeding 200 bytes; HTTP requests with Authorization headers from source IPs outside the admin allowlist receiving HTTP 200 responses from Silex management IPs; SYN-only outbound connections originating from Silex converter IP ranges to destinations outside the documented admin subnet; firmware-upload POSTs to SD-330AC web endpoints outside documented change windows; SNMP sysUpTime resets or cold/warmStart traps from SD-330AC assets outside maintenance schedule.

Host IOCs (adjacent Windows hosts): 4688 process-creation events for curl.exe, wget.exe, python.exe, pwsh.exe, or powershell.exe whose command line matches the Silex SIGMA 3 regex; 4104 PowerShell ScriptBlock events invoking Invoke-WebRequest or Invoke-RestMethod with target URIs ending in /login and POST bodies containing long redirect parameters; new executable writes matching silex\*.bin, sd330\*.img, or similar firmware images outside the documented AMC Manager install path.

OT/Operational IOCs: new CIP service codes, Modbus function codes, or OPC-UA method invocations originating from an SD-330AC IP and not present in the 30-day baseline; historian tag readings deviating from the 30-day baseline by more than 3 sigma coincident with an SD-330AC east-west flow; new asset fingerprint delta for any SD-330AC unit in Claroty, Dragos, Nozomi, Armis, Tenable OT, or Forescout outside change-window approvals; unexpected changes to SNMP sysName, sysContact, or sysLocation values on an SD-330AC.

# False Positive Baseline

The following known-good patterns will appear during the hunt and must be accounted for before escalation:

***- Vendor-scheduled firmware distribution windows — pre-documented in the change-management system — will legitimately produce firmware POST traffic and reboot events from AMC Manager to SD-330AC assets.***

Vulnerability scanning by Tenable.sc, Nessus, Qualys, Rapid7, or Claroty xDome enrichment pulls will generate sustained HTTP management-path requests from the scanner source IPs; scanner source addresses must be on the allowlist.

OT monitoring platform baseline-learning activities (Claroty CTD, Dragos, Nozomi, Armis, Tenable OT, Forescout) will generate light but persistent probes to OT assets including SD-330AC units for device-fingerprinting purposes.

Approved remote-support sessions by OEM integrators using AMC Manager over HTTPS from fixed vendor-egress IPs will match admin-authorization heuristics and must be cross-referenced against active engagement tickets.

NTP, SNMP-monitoring, and Zabbix/SolarWinds polling of SD-330AC units generates predictable low-rate management-plane traffic that will match SIGMA 1 destination selectors without matching the URL or redirect-length selectors.

Automated certificate renewal and configuration backup scripts run from the configuration management server may invoke curl or PowerShell against SD-330AC management endpoints on schedule; waive these by source host and schedule signature.

# Escalation Criteria

Escalate to the incident response team when any of the following conditions are met:

1. A single HTTP POST to an SD-330AC login endpoint contains a redirect= parameter exceeding 200 bytes from any source IP.

2. A successful HTTP 200 response to /login, /admin, or /password endpoints on an SD-330AC is observed from a source IP outside the documented admin allowlist.

3. An SD-330AC reports a sysUpTime reset, firmware-change syslog entry, or cold/warmStart SNMP trap outside the documented maintenance window.

4. An SD-330AC IP initiates a new east-west flow to a PLC, historian, medical device, or engineering workstation that is not present in the 30-day communication baseline.

5. A historian tag reading deviates from its 30-day baseline by more than 3 standard deviations within five minutes of an SD-330AC-originated management-plane event.

6. An SNMP sysName, sysContact, or sysLocation field on an SD-330AC changes outside a documented change window.

***7. Any YARA hit on Silex_Tampered_Firmware_Image (Section 5 YARA Rule 3) against a firmware image staged for or applied to an SD-330AC — correlate with vendor signing-key verification failure for automatic escalation.***

8. Any YARA hit on Silex_BridgeBreak_Inflight_Memory (Section 5 YARA Rule 2) against a live curl, wget, python, or PowerShell process on an admin host outside a documented penetration test.

***9. Any YARA hit on Silex_BridgeBreak_Exploit_OnDisk (Section 5 YARA Rule 1) against on-disk content on an admin or forensic host — correlate with the source and provenance of the file before closing.***

# Hunt Completion Criteria and Reporting

The hunt is considered complete when (a) every SD-330AC and AMC Manager asset identified in Section 1 has been queried for exploitation indicators across the full 30-day window, (b) every SIGMA, Snort/Suricata, and YARA rule in Section 5 has been executed against the relevant data source without producing an unresolved finding, (c) every OT monitoring platform export listed in Section 2 has been reviewed for baseline deviation, and (d) every false-positive pattern listed in Section 7 has been accounted for in the finding disposition.

The final hunt report must include: the enumerated SD-330AC and AMC Manager inventory and firmware state; the source queries and commands executed with timestamps; the hit count per detection rule with per-hit disposition (true positive, false positive, indeterminate); any escalations triggered under Section 8 and their downstream incident ticket references; and a remediation status summary identifying devices still on firmware version 1.42 or earlier and the planned upgrade date per device. Retain all hunt artifacts (PCAP, CSV exports, YARA output, platform exports) for a minimum of 180 days per organizational forensic retention policy.

# Advisory IoC Reference

| IOC Type | IOC |
|----|----|
| CVE | CVE-2026-32955 \| CVSS v3.1 8.8 \| Silex SD-330AC firmware 1.42 and earlier \| Authenticated stack-based buffer overflow via login redirect URL |
| CVE | CVE-2026-32956 \| CVSS v3.1 9.8 \| Silex SD-330AC firmware 1.42 and earlier \| Unauthenticated heap-based buffer overflow via login redirect URL (primary RCE primitive) |
| CVE | CVE-2026-32957 \| CVSS v3.1 5.3 \| Silex SD-330AC firmware 1.42 and earlier \| Unauthenticated arbitrary file upload to temporary storage |
| CVE | CVE-2026-32958 \| CVSS v3.1 6.5 \| Silex SD-330AC firmware 1.42 and earlier \| Hard-coded cryptographic signing key enables tampered firmware application |
| CVE | CVE-2026-32959 \| CVSS v3.1 5.9 \| Silex SD-330AC firmware 1.42 and earlier \| Weak encryption; constant keystream enables man-in-the-middle data theft |
| CVE | CVE-2026-32960 \| CVSS v3.1 6.5 \| Silex SD-330AC firmware 1.42 and earlier \| Authentication bypass via retained-credential reuse in crafted packet |
| CVE | CVE-2026-32961 \| CVSS v3.1 5.3 \| Silex SD-330AC firmware 1.42 and earlier \| Heap overflow resulting in DoS or potential RCE |
| CVE | CVE-2026-32962 \| CVSS v3.1 5.3 \| Silex SD-330AC firmware 1.42 and earlier \| Unauthenticated configuration modification (missing authentication) |
| CVE | CVE-2026-32963 \| CVSS v3.1 6.1 \| Silex SD-330AC firmware 1.42 and earlier \| Reflected cross-site scripting on system status page |
| CVE | CVE-2026-32964 \| CVSS v3.1 6.5 \| Silex SD-330AC firmware 1.42 and earlier \| Unauthenticated configuration injection inserting arbitrary entries |
| CVE | CVE-2026-32965 \| CVSS v3.1 7.5 \| Silex SD-330AC firmware 1.42 and earlier \| Insecure default initialization; null administrative password allows takeover |
| CVE | CVE-2015-5621 \| CVSS v3.1 7.5 \| Silex SD-330AC bundled SNMP agent \| Legacy net-snmp DoS terminating SNMP agent abnormally |
| CVE | CVE-2024-24487 \| CVSS v3.1 5.3 \| Silex SD-330AC firmware 1.42 and earlier \| Unauthenticated device reboot causing denial of service |
| Threat Actor | None specifically attributed — BRIDGE:BREAK was discovered and coordinated-disclosed by Forescout Research Vedere Labs (Francesco La Spina and Stanislav Dashevskyi); no named actor observed exploiting at disclosure |
| Malware | None published — no malware family has been attributed to Silex SD-330AC exploitation at time of disclosure |
| Network IOC | None published in source material — monitor https://www.cisa.gov/news-events/ics-advisories/icsa-26-111-10 for exploitation indicators |
| File IOC | None published in source material — monitor Forescout Vedere Labs disclosures and vendor advisory pages for released PoC artifacts |
| Behavioral | HTTP POST to SD-330AC /login endpoint with redirect= parameter exceeding 200 bytes |
| Behavioral | Successful HTTP 200 response to SD-330AC /login, /admin, or /password from source IP outside admin allowlist |
| Behavioral | SYN-only outbound connection from SD-330AC IP to destination outside documented admin subnet |
| Behavioral | SD-330AC sysUpTime reset, firmware-change syslog, or cold/warmStart SNMP trap outside maintenance window |
| Behavioral | New east-west flow from SD-330AC IP to PLC, historian, medical device, or engineering workstation absent from 30-day baseline |
| Behavioral | Unexpected change to SNMP sysName, sysContact, or sysLocation on SD-330AC outside documented change window |
| Behavioral | 4688 process-creation events for curl/wget/python/pwsh on admin hosts with command lines containing SD-330AC, long redirect parameter, set-password, or factory-default |
