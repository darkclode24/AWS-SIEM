# AWS CloudWatch-Based SIEM + Honeypot

_AWS-Hosted Security Information and Event Management (SIEM) using CloudWatch service with Cowrie Honeypot as data source, data and analytics are sanitized and visualized to a public Cloudfront dashboard._


## Architecture Overview

<br>

<div style="display: flex; justify-content: center; width: 100%;">
  <img src="arch.png" width="600" height="1200">
</div>  

<br>

## Operational Workflow

1. **Log Generation** | *EC2*
   User connects to TCP port 22 on EC2 instance &rarr; Cowrie records connections activities (usernames, passwords, commands, etc.) as JSON.
   <br>
2. **Log Transport** | *CloudWatch Agent*
   The Amazon CloudWatch Agent sends JSON events over HTTPS to CloudWatch Logs.
  <br>
3. **Centralized Logging** | *CloudWatch Logs*
   CloudWatch provides storage, search, dashboards, metric filters, alarms, and scheduled queries.
  <br>
4. **Event Routing** | *Amazon EventBridge*
   EventBridge receives alarm state changes and scheduled-query completion events.
  <br>
5. **Alert Processing** | *AWS Lambda*
   Detector Lambda converts matching events into alerts.
  <br>
6. **Notification** | *Amazon SNS*
   Amazon SNS sends alerts to telegram via Webhook.
  <br>
7. **Storage & Distribution** | *Amazon S3 & CloudFront*
   Private S3 bucket archives raw logs. A separate private S3 bucket and CloudFront distribution publish sanitized aggregate statistics for your portfolio.

## Services
Project uses the following AWS services :

| Services | Use |
|-|-|
| **Amazon EC2** | Hosts the Cowrie honeypot, configured with CloudWatch Agent and GeoLite2 |
| **Amazon CloudWatch** | Monitor honeypot activity and centralizes logs in CloudWatch Logs |
| **Amazon EventBridge** | Process and deliver Cloudwatch scheduled queries & alarms to Lambda |
| **Amazon Lambda** | Check whether result contains suspicious activity. If it does, send message to SNS |
| **Amazon SNS**  | Send reports to Telegram via Webhook |
| **Amazon S3**  | Archive logs from CloudWatch with 90-day deletion lifecycle |
| **Amazon Cloudfront**  | Deploy sanitized dashboard to public |



