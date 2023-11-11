import pulumi
import json
from pulumi_aws import ec2, get_availability_zones, rds, route53, iam
from pulumi import Config
import pulumi_aws as aws

# Create a Config instance
config = Config()

# Resource Tag
common_tag_value = config.require("commonTag")
common_tag = {"Name": common_tag_value}

# Fetch configurations
vpc_name = config.require("vpc_name")
vpc_cidr = config.require("vpc_cidr")
ami_id = config.require("ami_id")
instance_type = config.require("instanceType")
key_name = config.require("keyName")
volume_size = config.require_int("volumeSize")
volume_type = config.require("volumeType")
max_azs = config.require_int("maxAzs")
internet_cidr = config.require("internetCidr")
api_key = config.require_secret('api_key')
mailgun_domain = config.require("mailgun_domain")
mailgun_sender = config.require("mailgun_sender")
ses_region = config.require("ses_region")
ses_sender = config.require("ses_sender")

public_subnets_cidr = config.require_object("public_subnets_cidr")
private_subnets_cidr = config.require_object("private_subnets_cidr")

# Create a VPC
vpc = ec2.Vpc(vpc_name, cidr_block=vpc_cidr,
              enable_dns_support=True,
              enable_dns_hostnames=True,
              tags={**common_tag, "Type": "VPC"})

# Create an Internet Gateway
ig = ec2.InternetGateway("internetGateway", vpc_id=vpc.id,
                         tags={**common_tag, "Type": "Internet Gateway"})

# Get available AZs
azs = get_availability_zones().names
num_azs = min(len(azs), max_azs)  # Use a maximum of 3 AZs

# Create Public Subnets
public_subnets = []
for i, cidr in enumerate(public_subnets_cidr[:num_azs]):
    subnet = ec2.Subnet(f"publicSubnet-{i+1}",
                        vpc_id=vpc.id,
                        cidr_block=cidr,
                        availability_zone=azs[i],
                        map_public_ip_on_launch=True,
                        tags={**common_tag, "Type": f"publicSubnet-{i+1}"})
    public_subnets.append(subnet)

# Create Private Subnets
private_subnets = []
for i, cidr in enumerate(private_subnets_cidr[:num_azs]):
    subnet = ec2.Subnet(f"privateSubnet-{i+4}",
                        vpc_id=vpc.id,
                        cidr_block=cidr,
                        availability_zone=azs[i],
                        tags={**common_tag, "Type": f"privateSubnet-{i+4}"})
    private_subnets.append(subnet)

# Create Public Route Table
public_route_table = ec2.RouteTable("publicRouteTable", vpc_id=vpc.id, tags={
                                    **common_tag, "Type": "publicRouteTable"})
public_route = ec2.Route("publicRoute", route_table_id=public_route_table.id,
                         destination_cidr_block=internet_cidr, gateway_id=ig.id)

# Associate Public Subnets to Public Route Table
for i, subnet in enumerate(public_subnets):
    ec2.RouteTableAssociation(
        f"publicRta-{i}", route_table_id=public_route_table.id, subnet_id=subnet.id)

# Create Private Route Table
private_route_table = ec2.RouteTable("privateRouteTable", vpc_id=vpc.id, tags={
                                     **common_tag, "Type": "privateRouteTable"})

# Associate Private Subnets to Private Route Table
for i, subnet in enumerate(private_subnets):
    ec2.RouteTableAssociation(
        f"privateRta-{i}", route_table_id=private_route_table.id, subnet_id=subnet.id)

# RDS Subnet Group using private subnets
db_subnet_group = rds.SubnetGroup("dbSubnetGroup",
                                  name="csye6225-db-subnet-group",
                                  subnet_ids=[
                                      subnet.id for subnet in private_subnets],
                                  tags={**common_tag,
                                        "Type": "RDS DB Subnet Group"}
                                  )

# Application Security Group
application_sg = ec2.SecurityGroup("applicationSecurityGroup",
                                   vpc_id=vpc.id,
                                   description="Security group for application servers",
                                   ingress=[
                                       ec2.SecurityGroupIngressArgs(
                                           protocol="tcp", from_port=22, to_port=22, cidr_blocks=[internet_cidr]),
                                       ec2.SecurityGroupIngressArgs(
                                           protocol="tcp", from_port=80, to_port=80, cidr_blocks=[internet_cidr]),
                                       ec2.SecurityGroupIngressArgs(
                                           protocol="tcp", from_port=443, to_port=443, cidr_blocks=[internet_cidr]),
                                       ec2.SecurityGroupIngressArgs(
                                           protocol="tcp", from_port=8080, to_port=8080, cidr_blocks=[internet_cidr])
                                   ],
                                   egress=[
                                       ec2.SecurityGroupEgressArgs(
                                           protocol="tcp", from_port=3306, to_port=3306, cidr_blocks=[internet_cidr]),
                                       ec2.SecurityGroupEgressArgs(
                                           protocol="-1", from_port=0, to_port=0, cidr_blocks=[internet_cidr]),
                                   ],
                                   tags={**common_tag,
                                         "Type": "applicationSecurityGroup"}
                                   )
# DB Security Group
database_sg = ec2.SecurityGroup("databaseSecurityGroup",
                                vpc_id=vpc.id,
                                description="Security group for database servers",
                                egress=[
                                    ec2.SecurityGroupEgressArgs(
                                        protocol="-1", from_port=0, to_port=0, cidr_blocks=[internet_cidr]),
                                ],
                                ingress=[
                                    ec2.SecurityGroupIngressArgs(
                                        protocol="tcp",
                                        from_port=3306,
                                        to_port=3306,
                                        security_groups=[application_sg.id]
                                    ),
                                ],
                                tags={**common_tag,
                                      "Type": "databaseSecurityGroup"}
                                )

# RDS Parameter Group
db_parameter_group = rds.ParameterGroup(
    "dbparametergroup",
    name="dbparametergroup",
    family="mysql8.0",
    description=f"MySQL Parameter Group for {common_tag_value}",
    parameters=[
        {
            "name": "character_set_server",
            "value": "utf8"
        },
        {
            "name": "character_set_client",
            "value": "utf8"
        }
    ],
    tags=common_tag,
    opts=pulumi.ResourceOptions(delete_before_replace=True)
)


# RDS Instance
rds_instance = rds.Instance("csye6225",
                            engine="mysql",
                            engine_version="8.0",
                            instance_class="db.t3.micro",
                            allocated_storage=20,
                            storage_type="gp2",
                            username="csye6225",
                            password=config.require_secret("dbPassword"),
                            skip_final_snapshot=True,
                            parameter_group_name=db_parameter_group.name,
                            vpc_security_group_ids=[database_sg.id],
                            db_subnet_group_name=db_subnet_group.name,
                            identifier="csye6225",
                            tags=common_tag,
                            multi_az=False,
                            publicly_accessible=False,
                            apply_immediately=True,
                            name="csye6225",
                            )

# Split the RDS endpoint to remove the port number
hostname_only = rds_instance.endpoint.apply(
    lambda endpoint: endpoint.split(":")[0])


def create_user_data_script_values(hostname, endpoint, db_password, api_key, mailgun_domain, mailgun_sender, ses_region, ses_sender):
    return f"""#!/bin/bash
    set -e
    echo "User data script execution started" | sudo tee -a /var/log/cloud-init-output.log
    # Write environment variables to a separate file
    echo "DB_HOST={hostname}" | sudo tee -a /etc/webapp.env
    echo "DB_USERNAME=csye6225" | sudo tee -a /etc/webapp.env
    echo "DB_PASSWORD={db_password}" | sudo tee -a /etc/webapp.env
    echo "DB_NAME=csye6225" | sudo tee -a /etc/webapp.env
    echo "MAILGUN_API_KEY={api_key}" | sudo tee -a /etc/webapp.env
    echo "MAILGUN_DOMAIN={mailgun_domain}" | sudo tee -a /etc/webapp.env
    echo "MAILGUN_SENDER={mailgun_sender}" | sudo tee -a /etc/webapp.env

    # SES configuration
    echo "SES_REGION={ses_region}" | sudo tee -a /etc/webapp.env
    echo "SES_SENDER_EMAIL={ses_sender}" | sudo tee -a /etc/webapp.env

    # Echo the environment variables to the log
    echo "DB_HOST=${hostname}" | sudo tee -a /var/log/userdata.log
    echo "DB_USERNAME=csye6225" | sudo tee -a /var/log/userdata.log
    echo "DB_NAME=csye6225" | sudo tee -a /var/log/userdata.log
    echo "MAILGUN_DOMAIN=${mailgun_domain}" | sudo tee -a /var/log/userdata.log
    echo "MAILGUN_SENDER=${mailgun_sender}" | sudo tee -a /var/log/userdata.log
    echo "SES_REGION=${ses_region}" | sudo tee -a /var/log/userdata.log
    echo "SES_SENDER_EMAIL=${ses_sender}" | sudo tee -a /var/log/userdata.log

    # # Write the CloudWatch Agent Configuration to the file
    sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/cloudwatch-config.json

    # Restart the CloudWatch Agent to apply configurations
    sudo systemctl enable amazon-cloudwatch-agent
    sudo systemctl restart amazon-cloudwatch-agent

    echo "User data script execution completed" | sudo tee -a /var/log/cloud-init-output.log

    # Reload systemd 
    sudo systemctl daemon-reload

    # Introduce a delay before starting the service
    sleep 30
    sudo systemctl enable webapp.service
    sudo systemctl start webapp.service
    """


user_data_script = pulumi.Output.all(
    hostname_only, rds_instance.endpoint,
    config.require_secret('dbPassword'),
    config.require_secret('api_key'),
    pulumi.Output.from_input(mailgun_domain),
    pulumi.Output.from_input(mailgun_sender),
    pulumi.Output.from_input(ses_region),
    pulumi.Output.from_input(ses_sender)
)
user_data_script = user_data_script.apply(
    lambda args: create_user_data_script_values(*args))

# IAM Role for EC2
role = iam.Role("ec2Role",
                assume_role_policy=json.dumps({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Action": "sts:AssumeRole",
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "ec2.amazonaws.com"
                        }
                    }]
                }))

ses_policy = iam.Policy("sesPolicy",
                        description="Policy for allowing EC2 to send emails via SES",
                        policy=json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "ses:SendEmail",
                                    "ses:SendRawEmail",
                                    "ses:SendTemplatedEmail"
                                ],
                                "Resource": "*"
                            }]
                        }))

# Attach the custom SES policy to the role
ses_policy_attachment = iam.RolePolicyAttachment("sesPolicyAttachment",
                                                 role=role.name,
                                                 policy_arn=ses_policy.arn)


# List of policy ARNs you want to attach to the role
policies = [
    "arn:aws:iam::aws:policy/AmazonEC2FullAccess",
    "arn:aws:iam::aws:policy/AmazonRDSFullAccess",
    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    "arn:aws:iam::aws:policy/AmazonVPCFullAccess",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
    "arn:aws:iam::aws:policy/IAMUserChangePassword"
]

# Attach the policies to the role
for policy_arn in policies:
    attachment = aws.iam.RolePolicyAttachment(f'attach-{policy_arn.split(":")[-1]}',
                                              policy_arn=policy_arn,
                                              role=role.name)


# Create EC2 Instance Profile
instance_profile = iam.InstanceProfile("instanceProfile", role=role.name)


# EC2 Instance
ec2_instance = ec2.Instance("webInstance",
                            ami=ami_id,
                            instance_type=instance_type,
                            key_name=key_name,
                            iam_instance_profile=instance_profile.name,
                            user_data=user_data_script,
                            vpc_security_group_ids=[application_sg.id],
                            subnet_id=public_subnets[0].id,
                            opts=pulumi.ResourceOptions(
                                depends_on=[rds_instance]),
                            root_block_device=ec2.InstanceRootBlockDeviceArgs(
                                delete_on_termination=True,
                                volume_size=volume_size,
                                volume_type=volume_type
                            ),
                            tags={**common_tag, "Type": "webInstance"}
                            )

# Get the public IP of the EC2 instance
public_ip = ec2_instance.public_ip

# Accessing the hosted zone ID and domain name from the configuration
hosted_zone_id = config.require("hosted_zone_id")
domain_name = config.require("domain_name")

# A Record
a_record = route53.Record("aRecord",
                          name=domain_name,
                          type="A",
                          zone_id=hosted_zone_id,
                          ttl=60,
                          records=[public_ip])

# Outputs
pulumi.export("vpc_id", vpc.id)
pulumi.export("public_subnets", [subnet.id for subnet in public_subnets])
pulumi.export("private_subnets", [subnet.id for subnet in private_subnets])
pulumi.export("web_instance_id", ec2_instance.id)
pulumi.export('RDS Endpoint', rds_instance.endpoint)
pulumi.export("web_instance_public_ip", ec2_instance.public_ip)
pulumi.export("dns_a_record", a_record.fqdn)
