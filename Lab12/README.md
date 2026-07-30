# Asgard Cloud Security SOAR Platform

## Overview

The Asgard Cloud Security SOAR Platform is an AWS-based Security Orchestration, Automation, and Response (SOAR) solution that automates the detection, analysis, response, notification, and reporting of web application security events.

The platform uses an event-driven architecture built with AWS managed services and Infrastructure as Code (Terraform). It demonstrates how cloud-native services can work together to detect security events, correlate findings, generate incidents, notify responders, and produce executive-level security reports.

This project was completed as part of my AWS Cloud Computing coursework and showcases practical experience with AWS architecture, Terraform, serverless development, cloud security, and automation.

---

# Architecture

> **Architecture diagram goes here**

---

# Solution Workflow

## 1. AWS WAF

AWS WAF monitors incoming web requests and captures suspicious or malicious activity.

---

## 2. Amazon EventBridge

When a WAF event is generated, EventBridge routes the event to the Response Agent Lambda.

---

## 3. Response Agent

The Response Agent Lambda performs several tasks:

- Retrieves WAF event details
- Correlates security findings
- Determines severity
- Updates DynamoDB tables
- Sends notifications for significant events

---

## 4. Incident Management

Security findings and incidents are stored in Amazon DynamoDB.

The project uses multiple DynamoDB tables to separate:

- WAF events
- Correlation findings
- Security incidents

---

## 5. Notifications

Amazon SNS sends notifications for Medium and High severity incidents.

---

## 6. Executive Dashboard

The Executive Dashboard Lambda generates executive-friendly reports summarizing the overall security posture.

Reports are generated in:

- PDF
- JSON

and stored in Amazon S3.

---

# AWS Services Used

| AWS Service | Purpose |
|-------------|---------|
| AWS WAF | Detects malicious web traffic |
| Amazon EventBridge | Routes security events |
| AWS Lambda | Serverless event processing |
| Amazon DynamoDB | Stores findings and incidents |
| Amazon SNS | Sends security notifications |
| Amazon API Gateway | Provides secure API endpoint |
| Amazon Cognito | Authentication |
| Amazon Bedrock | AI-generated security summaries |
| Amazon S3 | Stores executive reports |
| Amazon CloudWatch | Logging and monitoring |
| AWS IAM | Least privilege security |
| Terraform | Infrastructure as Code |

---

# Repository Structure

```text
Lab12/
│
├── Lambda_Src/
│
├── waf.tf
├── apigateway.tf
├── lambda.tf
├── dynamodb.tf
├── eventbridge.tf
├── iam.tf
├── cognito.tf
├── cloudwatch.tf
├── sns.tf
├── s3.tf
├── bedrock.tf
│
├── waf-check.tf
├── lambda-check.tf
├── iam-check.tf
├── dynamodb-check.tf
├── apigateway-check.tf
├── cognito-check.tf
├── eventbridge-check.tf
├── sns-check.tf
├── s3-check.tf
│
└── outputs.tf
```

---

# Security Features

- AWS WAF protection
- Amazon Cognito authentication
- Least-privilege IAM policies
- Event-driven architecture
- Serverless design
- Terraform infrastructure validation using `check` blocks

---

# Executive Dashboard

The Executive Dashboard summarizes the overall security posture by generating reports containing:

- Executive Summary
- Overall Security Posture
- Key Security Metrics
- Material Changes
- Business Impact
- Leadership Attention Required

Reports are automatically uploaded to Amazon S3.

> **Executive Report screenshot goes here**

---

# Terraform Validation

This project makes extensive use of Terraform `check` blocks to validate infrastructure before deployment.

Examples include:

- IAM permissions
- DynamoDB permissions
- EventBridge permissions
- SNS permissions
- API Gateway configuration
- Cognito configuration
- S3 permissions
- WAF configuration

These checks help identify configuration issues before infrastructure is deployed.

---

# Technical Challenge

## Cross-Platform Lambda Packaging

During development on macOS, the Executive Dashboard Lambda failed with the following error:

```
Runtime.ImportModuleError
cannot import name '_imaging' from PIL
```

### Root Cause

The Pillow dependency contained native macOS (`darwin`) binaries that were incompatible with the AWS Lambda runtime.

### Solution

The dependencies were rebuilt using the official AWS Lambda Python 3.14 Docker image, producing Linux x86_64 compatible binaries before deployment.

This ensured that the Lambda runtime and packaged dependencies matched.

This was a good reminder that native Python libraries must be built for the same operating system and architecture used by the deployment environment.

---

# Skills Demonstrated

- AWS Architecture
- Terraform
- Infrastructure as Code
- Python
- AWS Lambda
- Amazon EventBridge
- Amazon DynamoDB
- Amazon SNS
- Amazon API Gateway
- Amazon Cognito
- Amazon Bedrock
- Amazon S3
- AWS IAM
- Cloud Security
- Event-Driven Architecture
- Serverless Development
- Docker
- Troubleshooting Native Python Dependencies

---

# Future Improvements

Some ideas I'd like to add in the future include:

- AI-generated remediation recommendations
- Historical security trend reporting
- Executive dashboard web application
- Multi-account AWS support
- Interactive security analytics
- Additional automation playbooks

---

# Lessons Learned

This project helped reinforce several cloud engineering concepts:

- Designing event-driven architectures
- Building serverless applications with AWS Lambda
- Applying least-privilege IAM principles
- Validating infrastructure with Terraform checks
- Packaging native Python dependencies for AWS Lambda
- Using Docker to build Linux-compatible deployment artifacts
- Troubleshooting infrastructure through incremental testing and verification

---

# Author

**Kevin Willocks**

AWS Solutions Architect Associate  
HashiCorp Terraform Associate

GitHub: *https://github.com/kevintestqa*

LinkedIn: *https://www.linkedin.com/in/kevinwillocks/*