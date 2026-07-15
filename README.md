# AWS CloudWatch-Based SIEM with Honeypot

_AWS-Hosted Security Information and Event Management (SIEM) using CloudWatch service with Cowrie Honeypot as data source, data and analytics are sanitized and visualized to a public Cloudfront dashboard._

## Architecture Overview

![Architecture Overview](images/arch.png)

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
| **Amazon Cloudfront** | Publishes the sanitized portfolio dashboard |

## Region

Regional service (_EC_) used in the project is placed in _Jakarta (ap-southeast-3)_. AWS-Managed services are global by default, so region-selection is not needed.

## Pricing Calculation

![Price Calculation](images/pricing-calc.png)

Estimated Monthly cost is **14.06 USD**. The cost covers one **EC2 Instances + gp3 EBS**, and one **Public IPv4 address**.

**CloudWatch, Lambda, SNS, S3 & CloudFront** will use Free Tier Plan, therefore the services will be free of charge.

## Budgeting

![Budget Dashboard](images/budgets.png)

Project service costs per month are tracked via AWS Budgets `Monthly Cost Limit`. Additionally, `Zero-Spend` alert is also configured to flag any unexpected resource usage before it accumulate cost.

# Getting Started - Preparing the AWS Account

Before starting, a separate IAM user named `bint-siem` is created instead of using the root user account for the project, following the _Principle of Least Privilege_ (PoLP). The user is then attached to a user group with only the permissions necessary for this project. 

![User Group Permissions](images/permissions.png)