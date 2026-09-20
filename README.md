# Signal / Intercept: AWS Serverless SIEM &amp; Threat Intelligence Honeypot

![Cover](images/cover.png)

![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-CloudFront-blue?style=flat&logo=amazon-aws)
![Technical Writeup](https://img.shields.io/badge/Technical_Writeup-WRITEUP.md-success?style=flat&logo=markdown)
![AWS](https://img.shields.io/badge/Cloud-AWS_ap--southeast--3-orange?style=flat&logo=amazon-aws)
![Python](https://img.shields.io/badge/Python-3.14-blue?style=flat&logo=python)
![Monthly Cost](https://img.shields.io/badge/Operating_Cost-~$14/mo-green?style=flat)

Signal / Intercept is an end-to-end, cloud-native Security Information and Event Management (SIEM) pipeline and threat intelligence sensor built entirely on AWS. 

It captures live internet attacks using a hardened Cowrie honeypot, detects intrusions in real time via Amazon CloudWatch Logs and AWS Lambda, sends sub-3-second alerts to Telegram, and visualizes global attack telemetry through an interactive 3D WebGL dashboard on Amazon CloudFront.

The entire production setup operates at **\~$14.06 USD per month** by combining a lightweight sensor with a 100% serverless detection and reporting architecture.

> **Looking for the in-depth implementation details?**  
> For the complete step-by-step deployment guide, firewall rules, CloudWatch Insights query syntax, and upstream bug patch, read the [Technical Writeup (WRITEUP.md)](./WRITEUP.md).

---

## Quick Links

- [Live Attack Dashboard](https://d35xk6zzbitrov.cloudfront.net/)
- [Full Technical Writeup](./WRITEUP.md)
- [Architecture &amp; Event Pipeline](#architecture--event-pipeline)
- [Key Engineering Highlights](#key-engineering-highlights)
- [Real-World Attack Telemetry](#real-world-attack-telemetry)
- [Visual Showcase](#visual-showcase)
- [Technology Stack](#technology-stack)
- [Repository Structure](#repository-structure)

---

## Key Highlights

- **Sub-3-Second Threat Alerting**: Replaced slow metric alarms with a CloudWatch Logs subscription filter that streams high-confidence events directly to AWS Lambda, delivering formatted Telegram alerts within 3 seconds of an attack.
- **Honeypot Isolation &amp; Kernel Containment**: The Cowrie sensor runs as an unprivileged user using Linux capabilities (`CAP_NET_BIND_SERVICE`) to bind port 22 directly. Host SSH is completely disabled in favor of AWS Systems Manager (SSM) Session Manager.
- **Egress Firewall with nftables**: Strict host-level egress rules allow payload downloads over HTTP and HTTPS while strictly blocking access to the AWS Instance Metadata Service (`169.254.169.254`), private RFC1918 subnets, and IPv6 routes. This prevents SSRF, credential theft, and botnet abuse.
- **Upstream Open-Source Bug Patch**: Diagnosed and resolved a silent crash in Cowrie 3.0.0's emulated `curl` command where servers omitting `Content-Length` triggered a `TypeError` on string sentinels, restoring automated malware capture.
- **Cost-Optimized Serverless Analytics**: A decoupled event architecture handles aggregate detections via EventBridge scheduled queries with a 20-minute lookback window, using Amazon DynamoDB TTL deduplication to prevent duplicate alerts.
- **Interactive 3D Threat Map**: An automated hourly pipeline aggregates logs into flat-cost daily buckets and serves an interactive WebGL globe via S3 and CloudFront with Origin Access Control (OAC).

---

## Architecture &amp; Event Pipeline

<p align="center">

  <img src="images/arch-new.png" alt="Architecture Overview" width="85%">

</p>

The system operates across four main pipeline stages:

**Ingress &amp; Sensor**

Attackers connect to the exposed Cowrie honeypot over TCP port 22. Cowrie emulates an authentic UNIX shell and logs auth attempts, terminal sessions, and file transfers as structured JSON.

**Ingestion &amp; Detection**

The CloudWatch Agent ships logs to `/honeypot/cowrie`. High-severity events (accepted logins, file uploads, payload drops) stream immediately to Lambda via a Subscription Filter.

**Correlation &amp; Deduplication**

Scheduled CloudWatch Logs Insights queries run every 5 minutes over a 20-minute lookback window to catch credential-guessing bursts. The detector Lambda validates records against DynamoDB TTL keys to prevent repeat alert fatigue.

**Alerting &amp; Visualization**

High-severity detections trigger Telegram notifications enriched with GeoIP flags. An hourly Lambda aggregates threat data into static JSON feeds served by Amazon CloudFront.

---

## Visual Showcase

### Interactive Threat Dashboard

The public-facing dashboard displays live geographic coordinates, top targeted usernames, captured passwords, shell commands, and malware transfer logs.

<p align="center">

  <a href="https://d35xk6zzbitrov.cloudfront.net/">

    <img src="images/public-dash.png" alt="Public Dashboard" width="90%">

  </a>

</p>

### Real-Time Telegram Threat Alerts

Alerts arrive in under 3 seconds and contain full contextual telemetry: detection type, source IP, country flag, credentials, shell commands, and file hashes.

<p align="center">

  <img src="images/telegram.png" alt="Telegram Alert" width="65%">

</p>

---

## Real-World Attack Telemetry

Data gathered over an initial 15-day live deployment window (July 29 to August 12, 2026):


| Metric                                | Captured Count         |
| :------------------------------------- | :---------------------- |
| **Total Inbound Connections**         | 2,123                  |
| **Brute-Force SSH Auth Attempts**     | 1,193                  |
| **Unique Attacker Source IPs**        | 293                    |
| **Simulated Shell Commands Recorded** | 276                    |
| **Malicious Payload Downloads**       | 8                      |
| **Malicious File Uploads**            | 9                      |
| **Alert Delivery Latency**            | &lt; 3 seconds         |
| **False Positive Rate**               | 0% (Honeypot baseline) |


---

## Technology Stack


| Layer                                  | Technologies &amp; Services                                                    |
| :-------------------------------------- | :------------------------------------------------------------------------------ |
| **Cloud Provider**                     | Amazon Web Services (AWS) - Jakarta Region (`ap-southeast-3`)                  |
| **Sensor &amp; Compute**               | Amazon EC2 (`t3.nano` / `t3.micro`), Cowrie Honeypot, Python 3.14              |
| **Operating System &amp; Security**    | Ubuntu Linux, `nftables`, Linux Capabilities (`CAP_NET_BIND_SERVICE`), AWS SSM |
| **Log Management &amp; Querying**      | Amazon CloudWatch Logs, CloudWatch Agent, Logs Insights                        |
| **Serverless Detection &amp; Routing** | AWS Lambda, Amazon EventBridge, Amazon SQS (Dead-Letter Queue)                 |
| **State &amp; Secret Management**      | Amazon DynamoDB (On-Demand with TTL), AWS Secrets Manager                      |
| **Notification Channel**               | Telegram Bot API, `ip-api.com` (GeoIP resolution)                              |
| **Storage &amp; Edge Delivery**        | Amazon S3 (Raw archive &amp; web hosting), Amazon CloudFront (OAC)             |
| **Frontend Visualization**             | Globe.gl (Three.js / WebGL), HTML5, Vanilla JavaScript, CSS3                   |
| **Automation**                         | PowerShell (`code/infra.ps1`), AWS CLI                                         |


---

## Writeup

All step-by-step configurations, firewall rules, code samples, and lessons learned have been organized into the dedicated technical writeup:

### [Read the Full Technical Writeup (WRITEUP.md)](./WRITEUP.md)

---

## Repository Structure

```
.
├── README.md               # Portfolio cover page and project summary
├── WRITEUP.md              # Complete technical writeup and implementation guide
├── images/                 # Architecture diagrams, dashboards, and alert screenshots
│   ├── arch-new.png        # System architecture diagram
│   ├── cover.png           # Repository cover banner
│   ├── public-dash.png     # WebGL 3D threat map screenshot
│   ├── telegram.png        # Telegram notification example
│   └── ...                 # Additional configuration and terminal screenshots
├── code/                   # Production backend scripts and automation
│   ├── lambda.py           # Detector Lambda (Subscription filter, EventBridge, Telegram)
│   ├── exporter.py         # Hourly threat intelligence aggregator and S3 publisher
│   ├── raw_archiver.py     # Real-time raw log stream archiver
│   └── infra.ps1           # Infrastructure-as-code deployment script
└── site/                   # Static dashboard frontend
    ├── index.html          # Dashboard markup
    ├── app.js              # Application logic and CloudFront data consumer
    ├── styles.css          # UI styles
    └── globe.gl.min.js     # 3D Globe visualization library
```

---

