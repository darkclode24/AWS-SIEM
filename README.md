# AWS CloudWatch-Based SIEM with Honeypot

AWS-Hosted Security Information and Event Management (SIEM) using CloudWatch service with Cowrie Honeypot as data source, data and analytics are sanitized and visualized to a public CloudFront dashboard.

## Architecture Overview

<p align="center">
  <img src="images/arch.png" alt="Architecture Overview" width="70%">
</p>

To-Dos:

- [ ] Change login success and credential-burst processing
- [ ] Unblock Cowrie's egress firewall
- [ ] Create Dashboard and viz

## Event Flow

1. Internet user connects to the Cowrie honeypot through TCP port 22.
2. Cowrie records auth attempts, commands, sessions, timestamps, etc. activity as JSON events.
3. CloudWatch Agent sends events to CloudWatch Logs.
4. CloudWatch stores and analyzes the logs using Logs Insights queries, metric filters, alarms, and dashboards.
5. Amazon EventBridge routes scheduled detection events & alarm state changes to detector Lambda function.
6. Lambda evaluates the results, generates an alert when suspicious activity is detected.
7. Alerts are delivered to Telegram through the notification pipeline.
8. Raw logs are archived in a private S3 bucket, while sanitized statistics are published through a separate S3 bucket and CloudFront distribution.

## Services

Project uses the following AWS services :

| Services | Use |
| - | - |
| **Amazon EC2** | Hosts the Cowrie honeypot, CloudWatch Agent and GeoLite2 DB |
| **Amazon CloudWatch** | Centralizes logs and provides queries, metrics, alarms, and dashboards |
| **Amazon EventBridge** | Routes scheduled detection events and alarm state changes |
| **Amazon Lambda** | Evaluates detection results and generates concise alerts |
| **Amazon SNS** | Distributes alert notifications |
| **Amazon S3** | Archives raw logs and stores sanitized dashboard data |
| **Amazon CloudFront** | Publishes the sanitized portfolio dashboard |

## Preparation

### Cowrie

  <img src="images/cowrie-logo.png" alt="Cowrie Logo" width="20%">

Cowrie is a medium- and high-interaction SSH and Telnet honeypot designed to capture brute-force attempts and record attacker activity. In this project, Cowrie operates in medium-interaction shell mode where it emulates UNIX environment in Python and serves as the primary source of data.

### Region

Regional resources in this project are deployed in the Asia Pacific (Jakarta) Region _(ap-southeast-3)_. CloudFront is a global service, while other resources (EC2, CloudWatch, Lambda, SNS, EventBridge, and S3) are configured in selected AWS Region.

### Pricing Calculation

![Price Calculation](images/pricing-calc.png)

Estimated Monthly cost is **14.06 USD** as per of `16 July 2026`. The cost covers one **EC2 Instances + 8GB gp3 EBS**, and one **Public IPv4 address**.

**CloudWatch, Lambda, SNS, S3 & CloudFront** will use Free Tier Plan and expected to remain within free tier usage, therefore the services will be free of charge.

### Budgeting

![Budget Dashboard](images/budgets.png)

Project service costs per month are tracked via AWS Budgets `Monthly Cost Limit`. Additionally, `Zero-Spend` alert is also configured to flag any unexpected resource usage before it accumulate cost.

### Account

Before starting, a separate IAM user named `bint-siem` is created instead of using the root user account for the project. The user is then attached to a user group with only the permissions necessary for this project, following the _Principle of Least Privilege_ (PoLP)

![User Group Permissions](images/permissions.png)

## Network

### VPC

![Resource Map](images/resource-map.png)

EC2 instance is deployed in a _Virtual Private Cloud_ (VPC) named `cowrie-siem-vpc` using `10.10.0.0/16` CIDR block, with a public subnet at `10.10.1.0/24`. This setup provides 251 IP addresses (AWS reserves 5 addresses) which is more than enough for the EC2 instance.

### Security Group

Security group is configured for `cowrie-siem-vpc` with inbound and outbound rules as below:

a. Inbound Rules

| Type | Protocol | Port | Source | Purpose
| - | - | - | - | - |
| SSH | TCP | 22 | `0.0.0.0/0` | Cowrie fake SSH service

b. Outbound Rules

| Type | Protocol | Port | Destination | Purpose
| - | - | - | - | - |
| HTTPS | TCP | 443 | `0.0.0.0/0` | SSM, CloudWatch, AWS APIs, HTTPS package repositories
| HTTP | TCP | 80 | `0.0.0.0/0` | If a package repository still requires HTTP

## EC2

### IAM role

![Resource Map](images/ec2-role.png)

EC2 instance is attached with a role with policies below:

a. `AmazonSSMManagedInstanceCore`: Enable AWS Systems Manager service core functionality

b. `CowrieCloudWatchLogsWrite` _(Inline Policy)_: Send logs only to `/honeypot/cowrie` CloudWatch Logs group

### Installing Cowrie

Before installing Cowrie, a dedicated unprevileged user and python venv are created. Running Cowrie without admin power limits impact if honeypot is compromised, venv keeps python dependencies isolated from the system environment.

After setup, `cowrie 3.0.0` is installed. Configuration is set as below after `cowrie init` is completed:

```
[honeypot]
hostname = srv-test-01
backend = shell
download_limit_size = 10485760

[ssh]
enabled = true
listen_endpoints = tcp:22:interface=0.0.0.0

[telnet]
enabled = false
```

Since ports 1-1023 normally requires root privileges, `CAP_NET_BIND_SERVICE` is used:

```
# Restrict the service's available capabilities
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Grant the capability required to bind to TCP port 22
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

Once configuration is set, give TCP 22 port to cowrie by disabling `ssh.service` and `ssh.socket`, and enabling / starting Cowrie.

![Cowrie](images/cowrie.png)

Note that SSH is no longer available, EC2 is accessed via AWS Systems Manager (SSM)

### Patch Cowrie curl command

`Cowrie 3.0.0` contains a bug in its emulated curl command.

```
src/cowrie/commands/curl.py  
```

When downloading from web servers that do not return a `Content-Length` header, Twisted sets `response.length` to the string sentinel `UNKNOWN_LENGTH`. Cowrie attempts to evaluate `self.totallength > limit_size`, raising `TypeError: '>' not supported between instances of 'str' and 'int'` and crashing the transfer silently.

The fix is to make `self.totallength` comparisons int-safe. The byte-level size limit in `collect()` remains fully enforced during transfer:

```python

# Before
if limit_size > 0 and self.totallength > limit_size:

# After
if limit_size > 0 and isinstance(self.totallength, int) and self.totallength > limit_size:  

```

### Filtering Cowrie outbound connections

After installing and configuring Cowrie on the EC2 instance, outbound traffic from `cowrie` user allows public HTTP (80) and HTTPS (443) payload retrieval, restrict DNS to local/VPC resolvers, and reject unsafe destinations (private IPs, EC2 metadata, IPv6).

```nftables

meta skuid ${COWRIE_UID} ip daddr { 127.0.0.53, 127.0.0.1, 10.10.0.2 } udp dport 53 accept
meta skuid ${COWRIE_UID} ip daddr { 127.0.0.53, 127.0.0.1, 10.10.0.2 } tcp dport 53 accept

meta skuid ${COWRIE_UID} ip daddr @unsafe_ipv4 ct state new \
  log prefix "cowrie-egress-unsafe " counter reject
meta skuid ${COWRIE_UID} ip6 daddr ::/0 ct state new \
  log prefix "cowrie-egress-ipv6 " counter reject

meta skuid ${COWRIE_UID} tcp dport { 80, 443 } accept

meta skuid ${COWRIE_UID} ct state new \
  log prefix "cowrie-egress-deny " counter reject

```

This rule is implemented using a custom script and persisted using systemd

After implementation, Cowrie can resolve names and fetch files over HTTP/HTTPS to capture downloads via `wget`/`curl`, but it cannot reach AWS metadata (`169.254.169.254`), private internal networks, IPv6, or non-HTTP ports.

![HTTP & HTTPS working](images/cowrie_connection.png)

>The VPC is IPv4-only today, so the IPv6 rule matches no traffic. However, because the firewall uses the `inet` family, any future IPv6 traffic would bypass the IPv4-only deny list, leaving egress unrestricted.

## Detecting the attackers

### CloudWatch Log Group

Created `/honeypot/cowrie` log group to receive logs from Cowrie EC2 instance.

### CloudWatch Agent

`AmazonCloudWatchAgent` package is installed to the EC2 instance via SSM &rarr; Run command, using `AWS-ConfigureAWSPackage` document.

CloudWatch agent is configured as below:

Source &rarr; `/log/cowrie/cowrie.json`
Target &rarr; `/honeypot/cowrie`

After configuration, CloudWatch agent successfully sends logs to CloudWatch Logs.

![CloudWatch Logs](images/CloudWatch-logs.png)

### Subscription Filter

CloudWatch Logs **subscription filter** streams successful login, and file transfer events directly to the detector Lambda.

One subscription filter named `cowrie-high-confidence-events` is configured on the `/honeypot/cowrie` log group with the pattern:

```pattern

{ ($.eventid = "cowrie.login.success") || ($.eventid = "cowrie.session.file_upload") || ($.eventid = "cowrie.session.file_download") }

```

| Setting | Value |
|---|---|
| Filter name | `cowrie-high-confidence-events` |
| Destination | Lambda function `cowrie-detector` |
| Log format | JSON |

CloudWatch Logs sends compressed events to Lambda. Lambda decodes and verifies the payload, maps the event to a detection type, and publishes SNS alert with key details (detection name, severity, timestamp, sensor alias, alert ID, and optional SHA-256).

| Cowrie event | Detection | Severity |
|---|---|---|
| `cowrie.login.success` | `COWRIE_EMULATED_AUTH_ACCEPTED` | HIGH |
| `cowrie.session.file_upload` | `COWRIE_FILE_UPLOADED` | HIGH |
| `cowrie.session.file_download` | `COWRIE_URL_PAYLOAD_DOWNLOADED` | HIGH |

Sensitive fields (source IP, username, password, session ID, URL, filename, local path) remain in private CloudWatch Logs and are never included in alert emails.

### Scheduled Query

CloudWatch's scheduled query is created to detect:

**a. Credential Attempts in honeypot**

  Accepted and rejected attempts are detected using query as below:

  ```
  fields "CREDENTIAL_GUESSING_BURST" as detection,
        src_ip,
        username,
        session
  | filter eventid = "cowrie.login.failed"
      or eventid = "cowrie.login.success"
  | stats count(*) as attempts,
          count_distinct(username) as usernames,
          count_distinct(session) as sessions
    by detection, src_ip
  | filter attempts >= 3
  | sort attempts desc
  ```

  The query is run every 15 minutes indefinitely, with lookback of 15 minutes.

**b. File-transfers in honeypot**

~~File uploads and downloads in Cowrie are detected using a scheduled Logs Insights query run every 5 minutes with a 5-minute lookback.~~

File uploads and downloads in Cowrie are detected using a metric filter and alarm. File transfer is a discrete high-confidence event, so it. Refer the _Metric Filter & Alarm_ section for the filter pattern and alarm configuration.

With outbound HTTPS allowed, Cowrie captures files fetched by attackers through `wget`/`curl` and stores them in `var/lib/cowrie/downloads/` with a SHA-256, so both SCP/SFTP transfers and `wget`/`curl` fetches produce `file_upload` or `file_download` events carrying the `url`, `filename`, and `shasum` fields.

### SNS

`cowrie-sec-alerts` SNS topic is created to be used for alerting via Telegram.

### Lambda

`cowrie-detector` function is created using configuration as below:

`python 3.14` runtime.
`timeout = 30 seconds` to allow the enrichment query to start and poll on file-transfer alarms
`env_variable = SNS_TOPIC_ARN`  to avoid hardcoding ARN
`env_variable = COWRIE_LOG_GROUP`  for the file-transfer enrichment query

Lambda code is available [here](code/lambda.py)

### EventBridge

Rule named `cowrie-login-success-to-detector` is created to receive `cowrie-login-success` alarm, and send it to `cowrie-detector` Lambda.

Another rule named `cowrie-file-transfer-to-detector` is created to receive `cowrie-file-transfer` alarm, and send it to `cowrie-detector` Lambda. The Lambda then runs a short enrichment query to attach file metadata to the alert.

Another rule named `cowrie-scheduled-queries-to-detector` is created to send scheduled queries to `cowrie-detector` Lambda.
