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

- **Near Real-Time Alerts & Deduplication**: CloudWatch Logs subscription filters push high-confidence events directly to Lambda for sub-second Telegram alerts, while scheduled Insights queries paired with DynamoDB TTL deduplicate high-volume credential bursts.
- **Defense-in-Depth Honeypot Isolation**: Cowrie runs unprivileged via systemd's `CAP_NET_BIND_SERVICE` with host SSH replaced by AWS SSM Session Manager, while strict `nftables` rules block AWS IMDS (`169.254.169.254`) and internal subnets while safely capturing payload downloads.
- **Cost-Optimized Static Dashboard**: An hourly Lambda compiles 24-hour telemetry into static JSON feeds on S3, served globally through Amazon CloudFront with Origin Access Control (OAC) and an interactive WebGL globe to keep query costs flat regardless of traffic.

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
  <img src="images/public-dash.png" alt="Public Dashboard" width="90%">
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

## Acknowledgements & Citations

This project integrates and builds upon several open-source tools, libraries, and datasets:

- **[Globe.gl](https://github.com/vasturiano/globe.gl)** by Vasco Asturiano – WebGL 3D globe visualization library used for the interactive threat map.
- **[Three.js](https://github.com/mrdoob/three.js)** by Ricardo Cabello (Mr.doob) & contributors – WebGL 3D rendering engine powering the globe visualization.
- **[World Atlas / TopoJSON](https://github.com/topojson/world-atlas)** by Mike Bostock & [Natural Earth](https://www.naturalearthdata.com/) – 1:110m vector geographic datasets (`site/countries-110m.json`) providing country polygon boundaries.
- **[Cowrie Honeypot](https://github.com/cowrie/cowrie)** by Michel Oosterhof & contributors – Medium-to-high interaction SSH sensor providing the raw telemetry stream.
- **[IP-API](https://ip-api.com/)** – IP geolocation batch API used by AWS Lambda to enrich attacker telemetry with coordinates and country data.
- **Typography** – [Fraunces](https://github.com/undercasetype/Fraunces) by Undercase Type and [IBM Plex Mono](https://github.com/IBM/plex) by IBM (SIL Open Font License).


