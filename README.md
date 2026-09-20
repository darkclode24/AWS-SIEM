# Signal / Intercept: AWS CloudWatch-Based SIEM &amp; Honeypot

![Cover](images/cover.png)

![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-CloudFront-blue?style=flat&logo=amazon-aws)
![Technical Writeup](https://img.shields.io/badge/Technical_Writeup-WRITEUP.md-success?style=flat&logo=markdown)
![AWS](https://img.shields.io/badge/AWS-ap--southeast--3-orange?style=flat&logo=amazon-aws)
![Monthly Cost](https://img.shields.io/badge/Estimated_Cost-~$14/mo-green?style=flat)

Signal / Intercept is a cloud-based SIEM and threat monitoring lab built on AWS. It uses an EC2 instance running a Cowrie honeypot as an SSH telemetry source, streams events into Amazon CloudWatch Logs, processes detections with AWS Lambda, sends real-time alerts to Telegram, and visualizes attacker activity on a public CloudFront dashboard.

The project runs for approximately **$14.06 USD per month** in the Jakarta region (`ap-southeast-3`), with the EC2 instance and its public IPv4 address accounting for nearly all of the cost. Alerting and data export tasks run on serverless services that fit comfortably within the AWS Free Tier.

> **Need the full implementation details?**  
> All configuration files, firewall rules, CloudWatch Insights query syntax, and code patches are documented in the [Technical Writeup (WRITEUP.md)](./WRITEUP.md).

---

## Overview &amp; Highlights

- **Near Real-Time Alerts via Subscription Filters**: Instead of waiting on metric alarm evaluation cycles, a CloudWatch Logs subscription filter sends high-confidence events (successful logins, file uploads, payload downloads) directly to Lambda. Alerts reach Telegram within seconds.
- **Privilege Separation on EC2**: Cowrie runs under an unprivileged user account. Using systemd's `CAP_NET_BIND_SERVICE`, the daemon binds port 22 directly without requiring root permissions. Host SSH is disabled in favor of AWS Systems Manager (SSM) Session Manager.
- **Egress Filtering with nftables**: Outbound traffic from the honeypot user is strictly limited. It allows HTTP/HTTPS downloads (to capture payloads) and local/VPC DNS lookups, while explicitly blocking access to the AWS Instance Metadata Service (`169.254.169.254`), private RFC1918 subnets, and non-HTTP ports.
- **Upstream Bug Fix**: Identified and patched an unhandled `TypeError` in Cowrie 3.0.0's emulated `curl` command. When servers returned responses without a `Content-Length` header, Cowrie compared an internal string sentinel against an integer, silently dropping file downloads. The fix keeps payload capture working against live servers.
- **Burst Deduplication with DynamoDB TTL**: CloudWatch Logs Insights scheduled queries run every 5 minutes with a 20-minute lookback window to catch credential-guessing bursts without missing delayed events. Lambda uses DynamoDB with a 25-minute TTL to suppress duplicate alerts for the same attacker IP across overlapping windows.
- **Static Public Dashboard**: An hourly Lambda function queries the last 24 hours of logs, geolocates source IPs, and generates static JSON feeds to S3. Amazon CloudFront serves the frontend and an interactive WebGL globe with Origin Access Control (OAC), keeping query costs flat regardless of traffic.

---

## Architecture &amp; Data Flow

<p align="center">

  <img src="images/arch-new.png" alt="Architecture Overview" width="85%">

</p>

The telemetry pipeline operates across four stages:

**Sensor Ingress**

Attackers connect to Cowrie on port 22. The honeypot simulates a UNIX shell, logging authentication attempts, interactive sessions, and file transfers as structured JSON.

**Log Collection**

The CloudWatch Agent writes the local JSON log to `/honeypot/cowrie`. High-confidence events stream immediately to the detector Lambda via a Subscription Filter.

**Burst Detection &amp; Deduplication**

Scheduled CloudWatch Logs Insights queries run every 5 minutes to identify credential-guessing bursts (5 or more attempts per IP). When EventBridge signals query completion, Lambda checks DynamoDB to suppress repeated alerts for known attackers.

**Alerting &amp; Web Export**

Qualified events are sent to Telegram with source country flags and event context. Separately, an hourly export Lambda generates static JSON documents for the public dashboard.

---

## Visual Showcase

### Live Threat Dashboard

The public dashboard shows attacker coordinates on a 3D globe along with top targeted usernames, passwords, shell commands, and captured downloads.

<p align="center">

  <a href="https://d35xk6zzbitrov.cloudfront.net/">

    <img src="images/public-dash.png" alt="Public Dashboard" width="90%">

  </a>

</p>

### Telegram Notifications

Alerts include detection type, attacker IP, country flag, credentials, shell commands, and file metadata.

<p align="center">

  <img src="images/telegram.png" alt="Telegram Alert" width="60%">

</p>

---

## Attack Telemetry (Initial 15-Day Sample)

The table below summarizes activity captured during an initial 15-day observation window (July 29 to August 12, 2026):


| Metric                          | Count |
| :------------------------------- | :----- |
| **Total Inbound Connections**   | 2,123 |
| **SSH Authentication Attempts** | 1,193 |
| **Unique Attacker Source IPs**  | 293   |
| **Shell Commands Entered**      | 276   |
| **Payload Downloads Captured**  | 8     |
| **File Uploads Captured**       | 9     |


All 17 file-transfer and payload events generated immediate Telegram alerts with the associated source IP and payload details.

---

## Technologies Used


| Category                     | Tools &amp; Services                                                           |
| :---------------------------- | :------------------------------------------------------------------------------ |
| **Cloud Provider**           | Amazon Web Services (AWS) in Jakarta (`ap-southeast-3`)                        |
| **Compute &amp; Sensor**     | Amazon EC2, Cowrie Honeypot, Python                                            |
| **Host Security**            | Ubuntu Linux, `nftables`, Linux Capabilities (`CAP_NET_BIND_SERVICE`), AWS SSM |
| **Logging &amp; Queries**    | Amazon CloudWatch Logs, CloudWatch Agent, Logs Insights                        |
| **Serverless Logic**         | AWS Lambda, Amazon EventBridge, Amazon SQS (Dead-Letter Queue)                 |
| **State &amp; Secrets**      | Amazon DynamoDB (On-Demand with TTL), AWS Secrets Manager                      |
| **Alerts &amp; Geolocation** | Telegram Bot API, `ip-api.com`                                                 |
| **Storage &amp; CDN**        | Amazon S3, Amazon CloudFront (Origin Access Control)                           |
| **Frontend**                 | Globe.gl (Three.js / WebGL), HTML5, JavaScript, CSS3                           |
| **Deployment**               | PowerShell automation (`code/infra.ps1`), AWS CLI                              |


---

## Technical Writeup

Detailed installation steps, configuration files, and troubleshooting notes are documented in:

### [Read the Full Technical Writeup (WRITEUP.md)](./WRITEUP.md)

What is covered in the writeup:

- AWS pricing breakdown ($14.06/month) and budget alert setup
- VPC network topology, subnets, and security group rules
- Cowrie service configuration and systemd capability binding
- Root-cause analysis and code fix for the Cowrie curl bug
- Complete `nftables` egress filtering script
- CloudWatch subscription filter patterns and Logs Insights query syntax
- DynamoDB TTL deduplication table structure and query overlap handling
- Dashboard export design and PowerShell deployment script
- Lessons learned from operating a public sensor

---

## Repository Structure

```
.
├── README.md               # Project overview and portfolio summary
├── WRITEUP.md              # Technical writeup and implementation details
├── images/                 # Architecture diagrams, dashboards, and alert screenshots
│   ├── arch-new.png        # System architecture diagram
│   ├── cover.png           # Repository cover banner
│   ├── public-dash.png     # WebGL 3D threat map screenshot
│   ├── telegram.png        # Telegram notification example
│   └── ...                 # Additional configuration and terminal screenshots
├── code/                   # Production scripts and backend handlers
│   ├── lambda.py           # Detector Lambda (subscription filter & scheduled query handler)
│   ├── exporter.py         # Hourly threat data aggregator and S3 publisher
│   ├── raw_archiver.py     # Raw log stream archiver
│   └── infra.ps1           # Infrastructure deployment script
└── site/                   # Static dashboard frontend
    ├── index.html          # Dashboard markup
    ├── app.js              # Application logic and CloudFront data consumer
    ├── styles.css          # UI styles
    └── globe.gl.min.js     # 3D Globe visualization library
```

---

## Author

**Bintang Darmawan**  
Computer Engineering | Cloud &amp; Cybersecurity Enthusiast  
Palembang, South Sumatra, Indonesia

- **LinkedIn**: [linkedin.com/in/bintang-darmawan](https://linkedin.com/in/bintang-darmawan)
- **GitHub**: [github.com/darkclode24](https://github.com/darkclode24)
- **Email**: [bintdar.dev@gmail.com](mailto:bintdar.dev@gmail.com)

