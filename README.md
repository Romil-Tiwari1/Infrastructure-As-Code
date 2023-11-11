# AWS Infrastructure with Pulumi

## Overview
# AWS Infrastructure with Pulumi

## Overview

This project utilizes Pulumi for infrastructure as code (IaC) to provision AWS resources for a web application. It includes the setup of a VPC, EC2 instances, RDS, Route53 DNS configuration, CloudWatch for logging and metrics, IAM roles, and policies, along with AMI updates using Packer.

## Prerequisites

- Pulumi CLI
- Python 3.x
- AWS CLI configured with your credentials
- Pulumi AWS Plugin (`pulumi plugin install resource aws v4.0.0`)

## Configurations

Use the following Pulumi commands to set up your configurations:

```bash
pulumi config set aws:region <aws-region>
pulumi config set vpc_name <vpc-name>
pulumi config set vpc_cidr <cidr-block>
# Add other configurations as necessary
```

## Infrastructure Components

### Networking
- VPC with custom CIDR
- Internet Gateway
- Route Tables
- Subnets across multiple AZs
### Compute
- EC2 Instances with user data scripts
- Security Groups for EC2 with ingress rules for application ports
### Database
- RDS Instances with DB Security Groups
### DNS
- Route53 A Record setup for domain pointing to EC2 Instances
### Logging and Metrics
- CloudWatch Agent setup on EC2 Instances
### Custom Metrics with CloudWatch
- IAM roles for CloudWatch logging
### IAM
- IAM Roles and Policies for required AWS resource access
### AMI
- Packer templates for AMI with CloudWatch Agent

## Deployment Instructions
### Clone the Repository:

```bash
git clone https://github.com/CloudProdOrg/iac-pulumi.git
cd iac-pulumi
```
### Initialize a Virtual Environment (optional but recommended):

```bash
python -m venv venv
source venv/bin/activate  # Use `venv\Scripts\activate` on Windows
```
### Install Dependencies:

```bash
pip install -r requirements.txt
```

### Deploy with Pulumi:

```bash
pulumi up -y
```
### Verify Deployment:

- Inspect the created resources in the AWS console or using AWS CLI.

### Destroy Resources (optional):

```bash
pulumi destroy -y
```

## Notes
- Ensure the AWS region and CIDR blocks are configured according to your requirements.
- Update the Packer template to include the Unified CloudWatch Agent in your AMIs.
- Attach the IAM role for the CloudWatch agent to the EC2 instance via Pulumi.
- The userdata script should configure the CloudWatch agent and restart it upon launch.
- Route53 will update the DNS A record to point your domain to the newly created EC2 instance.


Please ensure to replace `<aws-region>`, `<vpc-name>`, and `<cidr-block>` with the actual values you intend to use. Once you've made these replacements, you can save this content as `README.md` in the root of your GitHub repository.