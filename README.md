# AWS CloudWatch-Based SIEM + Honeypot

_AWS-Hosted Security Information and Event Management (SIEM) using CloudWatch service with Cowrie Honeypot as source, data and analytics are sanitized and visualized to a public Cloudfront_


## Architecture Overview

<br>

<div style="display: flex; justify-content: center; width: 100%;">
  <img src="arch.png" width="600" height="1200">
</div>  

<br>


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



