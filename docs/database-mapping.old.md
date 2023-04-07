## Mapping list

Here a summary from database.

-   MITRE ATT&CK *v.12*

    -   Tactics: 11

    -   Techniques: 61

-   AWS Service & Events

    -   AmazonCognito: 4

    -   AmazonGuardDuty: 55

    -   AmazonInspector: 5

    -   AmazonMacie: 10

    -   AmazonVirtualPrivatecloud: 3

    -   AWSCloudHSM: 1

    -   AWSCloudWatch: 3

    -   AWSConfig: 114

    -   AWSIAM: 5

    -   AWSIOTDeviceDefender: 31

    -   AWSKeyManagementService: 1

    -   AWSNetworkFirewall: 4

    -   AWSOrganizations: 3

    -   AWSRDS: 4

    -   AWSS3: 1

    -   AWSSecretsManager: 1

    -   AWSSecurityHub: 34

    -   AWSSSO: 3

    -   AWSWebApplicationFirewall: 4

-   CIS CSC *v8*

    -   Controls: 142

-   NIST *800-53-rev5*

    -   Controls: 135

-   PCI-DSS *v3.2.1*

    -   Controls: 147

-   ISO *27K (001,002,017,018)*

    -   Controls: 23

-   C5 *(2022)*

    -   Controls: 17

-   ENS CNN-STICK *(2022)*

    -   Controls: 17

### MITRE ATT&CK Tactics

-   TA0001 Initial Access

-   TA0002 Execution

-   TA0003 Persistence

-   TA0004 Privilege Escalation

-   TA0005 Defense Evasion

-   TA0006 Credential Access

-   TA0007 Discovery

-   TA0008 Lateral Movement

-   TA0009 Collection

-   TA0010 Exfiltration

-   TA0040 Impact

### MITRE ATT&CK Techniques

-   T1040 Network Sniffing

-   T1046 Network Service Discovery

-   T1078 Valid Accounts

-   T1078.001 Valid Accounts: Default Accounts

-   T1078.004 Valid Accounts: Cloud Accounts

-   T1087.004 Account Discovery: Cloud Account

-   T1098 Account Manipulation

-   T1098.001 Account Manipulation: Additional Cloud Credentials

-   T1098.004 Account Manipulation: SSH Authorized Keys

-   T1110 Brute Force

-   T1110.001 Brute Force: Password Guessing

-   T1110.002 Brute Force: Password Cracking

-   T1110.003 Brute Force: Password Spraying

-   T1110.004 Brute Force: Credential Stuffing

-   T1119 Automated Collection

-   T1136 Create Account

-   T1136.003 Create Account: Cloud Account

-   T1189 Drive-by Compromise

-   T1190 Exploit Public-Facing Application

-   T1199 Trusted Relationship

-   T1201 Password Policy Discovery

-   T1204 User Execution

-   T1204.003 User Execution: Malicious Image

-   T1485 Data Destruction

-   T1486 Data Encrypted for Impact

-   T1491 Defacement

-   T1491.002 Defacement: External Defacement

-   T1496 Resource Hijacking

-   T1498 Network Denial of Service

-   T1498.001 Network Denial of Service: Direct Network Flood

-   T1498.002 Network Denial of Service: Reflection Amplification

-   T1499.002 Endpoint Denial of Service: Service Exhaustion Flood

-   T1499.003 Endpoint Denial of Service: Application Exhaustion Flood

-   T1499.004 Endpoint Denial of Service: Application or System Exploitation

-   T1525 Implant Internal Image

-   T1526 Cloud Service Discovery

-   T1528 Steal Application Access Token

-   T1530 Data from Cloud Storage Object

-   T1531 Account Access Removal

-   T1535 Unused/Unsupported Cloud Regions

-   T1537 Transfer Data to Cloud Account

-   T1538 Cloud Service Dashboard

-   T1550 Use Alternate Authentication Material

-   T1550.001 Use Alternate Authentication Material: Application Access Token

-   T1552 Unsecured Credentials

-   T1552.001 Unsecured Credentials: Credentials In Files

-   T1552.005 Unsecured Credentials: Cloud Instance Metadata API

-   T1562 Impair Defenses

-   T1562.001 Impair Defenses: Disable or Modify Tools

-   T1562.007 Impair Defenses: Disable or Modify Cloud Firewall

-   T1562.008 Impair Defenses: Disable Cloud Logs

-   T1566 Phishing

-   T1578 Modify Cloud Compute Infrastructure

-   T1578.001 Modify Cloud Compute Infrastructure: Create Snapshot

-   T1578.002 Modify Cloud Compute Infrastructure: Create Cloud Instance

-   T1578.003 Modify Cloud Compute Infrastructure: Delete Cloud Instance

-   T1578.004 Modify Cloud Compute Infrastructure: Revert Cloud Instance

-   T1580 Cloud Infrastructure Discovery

-   T1619 Cloud Storage Object Discovery

-   T1621 Multi-Factor Authentication Request Generation

-   T1648 Serverless Execution

### AWS Service / Event rule

-   AmazonCognito

    **Event rule:**

    CredentialAccess:IAMUser/AnomalousBehavior

    iam-password-policy

    iam-user-mfa-enabled

    Impact:EC2/WinRMBruteForce

-   AmazonGuardDuty

    **Event rule:**

    Backdoor:EC2/DenialOfService.Dns

    Backdoor:EC2/DenialOfService.Tcp

    Backdoor:EC2/DenialOfService.Udp

    Backdoor:EC2/DenialOfService.UdpOnTcpPorts

    Backdoor:EC2/DenialOfService.UnusualProtocol

    CredentialAccess:IAMUser/AnomalousBehavior

    CryptoCurrency:EC2/BitcoinTool.B

    CryptoCurrency:EC2/BitcoinTool.B!DNS

    DefenseEvasion:IAMUser/AnomalousBehavior

    Discovery:IAMUser/AnomalousBehavior

    Discovery:S3/MaliciousIPCaller

    Discovery:S3/MaliciousIPCaller.Custom

    Discovery:S3/TorIPCaller

    Exfiltration:IAMUser/AnomalousBehavior

    Exfiltration:S3/MaliciousIPCaller

    Impact:EC2/BitcoinDomainRequest.Reputation

    Impact:EC2/PortSweep

    Impact:EC2/WinRMBruteForce

    Impact:IAMUser/AnomalousBehavior

    Impact:S3/MaliciousIPCaller

    PenTest:IAMUser/KaliLinux

    PenTest:IAMUser/ParrotLinux

    PenTest:IAMUser/PentooLinux

    PenTest:S3/KaliLinux

    PenTest:S3/ParrotLinux

    PenTest:S3/PentooLinux

    Persistence:IAMUser/AnomalousBehavior

    Policy:IAMUser/RootCredentialUsage

    Policy:S3/AccountBlockPublicAccessDisabled

    Policy:S3/BucketAnonymousAccessGranted

    Policy:S3/BucketBlockPublicAccessDisabled

    Policy:S3/BucketPublicAccessGranted

    Recon:EC2/PortProbeEMRUnprotectedPort

    Recon:EC2/PortProbeUnprotectedPort

    Recon:EC2/Portscan

    Recon:IAMUser/MaliciousIPCaller

    Recon:IAMUser/MaliciousIPCaller.Custom

    Recon:IAMUser/TorIPCaller

    Stealth:IAMUser/CloudTrailLoggingDisabled

    Stealth:IAMUser/PasswordPolicyChange

    Stealth:S3/ServerAccessLoggingDisabled

    Trojan:EC2/DriveBySourceTraffic!DNS

    Trojan:EC2/PhishingDomainRequest!DNS

    UnauthorizedAccess:EC2/MetadataDNSRebind

    UnauthorizedAccess:EC2/RDPBruteForce

    UnauthorizedAccess:EC2/SSHBruteForce

    UnauthorizedAccess:EC2/TorRelay

    UnauthorizedAccess:IAMUser/ConsoleLogin

    UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B

    UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration

    UnauthorizedAccess:IAMUser/MaliciousIPCaller

    UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom

    UnauthorizedAccess:IAMUser/TorIPCaller

    UnauthorizedAccess:S3/MaliciousIPCaller.Custom

    UnauthorizedAccess:S3/TorIPCaller

-   AmazonInspector

    **Event rule:**

    iam-password-policy

    Recon:EC2/Portscan

    Trojan:EC2/DriveBySourceTraffic!DNS

    UnauthorizedAccess:EC2/MetadataDNSRebind

    UnauthorizedAccess:EC2/SSHBruteForce

-   AmazonMacie

    **Event rule:**

    Policy:IAMUser/S3BlockPublicAccessDisabled

    Policy:IAMUser/S3BucketEncryptionDisabled

    Policy:IAMUser/S3BucketPublic

    Policy:IAMUser/S3BucketReplicatedExternally

    Policy:IAMUser/S3BucketSharedExternally

    SensitiveData:S3Object/Credentials

    SensitiveData:S3Object/CustomIdentifier

    SensitiveData:S3Object/Financial

    SensitiveData:S3Object/Multiple

    SensitiveData:S3Object/Personal

-   AmazonVirtualPrivatecloud

    **Event rule:**

    Backdoor:EC2/DenialOfService.Dns

    elb-tls-https-listeners-only

    Recon:EC2/Portscan

-   AWSCloudHSM

    **Event rule:**

    encrypted-volumes

-   AWSCloudWatch

    **Event rule:**

    CryptoCurrency:EC2/BitcoinTool.B

    elb-tls-https-listeners-only

    access-keys-rotated

-   AWSConfig

    **Event rule:**

    acm-certificate-expiration-check

    alb-http-drop-invalid-header-enabled

    alb-http-to-https-redirection-check

    alb-waf-enabled

    api-gw-associated-with-waf

    api-gw-cache-enabled-and-encrypted

    api-gw-execution-logging-enabled

    api-gw-ssl-enabled

    autoscaling-group-elb-healthcheck-required

    autoscaling-launch-config-public-ip-disabled

    beanstalk-enhanced-health-reporting-enabled

    cloud-trail-cloud-watch-logs-enabled

    cloudtrail-enabled

    cloud-trail-encryption-enabled

    cloud-trail-log-file-validation-enabled

    cloudtrail-s3-dataevents-enabled

    cloudtrail-security-trail-enabled

    cloudwatch-alarm-action-check

    cloudwatch-log-group-encrypted

    cmk-backing-key-rotation-enabled

    codebuild-project-envvar-awscred-check

    codebuild-project-source-repo-url-check

    db-instance-backup-enabled

    dms-replication-not-public 

    dynamodb-in-backup-plan

    dynamodb-pitr-enabled

    dynamodb-throughput-limit-check

    ebs-in-backup-plan

    ebs-snapshot-public-restorable-check

    ec2-ebs-encryption-by-default

    ec2-imdsv2-check

    ec2-instance-managed-by-systems-manager

    ec2-instance-no-public-ip

    ec2-instance-profile-attached

    ec2-instances-in-vpc

    ec2-managedinstance-patch-compliance-status-check

    ec2-security-group-attached-to-eni

    ecs-containers-nonprivileged

    ecs-containers-readonly-access

    efs-access-point-enforce-root-directory

    efs-access-point-enforce-user-identity

    efs-encrypted-check

    efs-in-backup-plan

    elasticache-redis-cluster-automatic-backup-check

    elastic-beanstalk-managed-updates-enabled

    elasticsearch-encrypted-at-rest

    elasticsearch-in-vpc-only

    elasticsearch-logs-to-cloudwatch

    elasticsearch-node-to-node-encryption-check

    elb-acm-certificate-required

    elb-cross-zone-load-balancing-enabled

    elb-deletion-protection-enabled

    elb-logging-enabled

    elb-predefined-security-policy-ssl-check

    elb-tls-https-listeners-only

    elbv2-acm-certificate-required

    emr-kerberos-enabled

    emr-master-no-public-ip

    encrypted-volumes

    iam-password-policy

    iam-policy-no-statements-with-admin-access

    iam-policy-no-statements-with-full-access

    iam-root-access-key-check

    iam-user-group-membership-check

    iam-user-mfa-enabled

    iam-user-unused-credentials-check

    internet-gateway-authorized-vpc-only

    lambda-concurrency-check

    lambda-function-public-access-prohibited

    mfa-enabled-for-iam-console-access

    multi-region-cloudtrail-enabled

    opensearch-access-control-enabled

    rds-automatic-minor-version-upgrade-enabled

    rds-enhanced-monitoring-enabled

    rds-in-backup-plan

    rds-instance-deletion-protection-enabled

    rds-instance-public-access-check

    rds-logging-enabled

    rds-multi-az-support

    rds-snapshot-encrypted

    rds-snapshots-public-prohibited

    rds-storage-encrypted

    redshift-backup-enabled

    redshift-cluster-configuration-check

    redshift-cluster-kms-enabled

    redshift-cluster-maintenancesettings-check

    redshift-cluster-public-access-check

    redshift-enhanced-vpc-routing-enabled

    redshift-require-tls-ssl

    restricted-common-ports

    restricted-ssh

    root-account-hardware-mfa-enabled

    root-account-mfa-enabled

    s3-account-level-public-access-blocks-periodic

    s3-bucket-acl-prohibited

    s3-bucket-default-lock-enabled

    s3-bucket-level-public-access-prohibited

    s3-bucket-logging-enabled 

    s3-bucket-public-read-prohibited

    s3-bucket-public-write-prohibited

    s3-bucket-replication-enabled

    s3-bucket-server-side-encryption-enabled

    s3-bucket-ssl-requests-only

    s3-bucket-versioning-enabled

    sagemaker-endpoint-configuration-kms-key-configured

    sagemaker-notebook-instance-kms-key-configured

    sagemaker-notebook-no-direct-internet-access

    securityhub-enabled

    sns-encrypted-kms

    ssm-document-not-public

    subnet-auto-assign-public-ip-disabled

    vpc-flow-logs-enabled

    vpc-sg-open-only-to-authorized-ports

    wafv2-logging-enabled

-   AWSIAM

    **Event rule:**

    Discovery:IAMUser/AnomalousBehavior

    iam-user-mfa-enabled

    Impact:IAMUser/AnomalousBehavior

    multi-region-cloudtrail-enabled

    Persistence:IAMUser/AnomalousBehavior

-   AWSIOTDeviceDefender

    **Event rule:**

    AUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK

    aws:all-bytes-in

    aws:all-bytes-out

    aws:all-packets-in

    aws:all-packets-out

    aws:destination-ip-addresses

    aws:listening-tcp-ports

    aws:listening-udp-ports

    aws:message-byte-size

    aws:num-authorization-failures

    aws:num-connection-attempts

    aws:num-disconnects

    aws:num-established-tcp-connections

    aws:num-listening-tcp-ports

    aws:num-listening-udp-ports

    aws:num-messages-received

    aws:num-messages-sent

    aws:source-ip-address

    CA_CERTIFICATE_EXPIRING_CHECK

    CA_CERTIFICATE_KEY_QUALITY_CHECK

    CONFLICTING_CLIENT_IDS_CHECK

    DEVICE_CERTIFICATE_EXPIRING_CHECK

    DEVICE_CERTIFICATE_KEY_QUALITY_CHECK

    DEVICE_CERTIFICATE_SHARED_CHECK

    IOT_POLICY_OVERLY_PERMISSIVE_CHECK

    IOT_ROLE_ALIAS_ALLOWS_ACCESS_TO_UNUSED_SERVICES_CHECK

    IOT_ROLE_ALIAS_OVERLY_PERMISSIVE_CHECK

    LOGGING_DISABLED_CHECK

    REVOKED_CA_CERTIFICATE_STILL_ACTIVE_CHECK

    REVOKED_DEVICE_CERTIFICATE_STILL_ACTIVE_CHECK

    UNAUTHENTICATED_COGNITO_ROLE_OVERLY_PERMISSIVE_CHECK

-   AWSKeyManagementService

    **Event rule:**

    encrypted-volumes

-   AWSNetworkFirewall

    **Event rule:**

    Backdoor:EC2/DenialOfService.Dns

    elb-cross-zone-load-balancing-enabled

    Exfiltration:S3/MaliciousIPCaller

    Recon:EC2/Portscan

-   AWSOrganizations

    **Event rule:**

    Discovery:IAMUser/AnomalousBehavior

    Exfiltration:IAMUser/AnomalousBehavior

    mfa-enabled-for-iam-console-access

-   AWSRDS

    **Event rule:**

    elb-tls-https-listeners-only

    rds-automatic-minor-version-upgrade-enabled

    rds-instance-deletion-protection-enabled

    rds-storage-encrypted

-   AWSS3

    **Event rule:**

    s3-bucket-versioning-enabled

-   AWSSecretsManager

    **Event rule:**

    Impact:IAMUser/AnomalousBehavior

-   AWSSecurityHub

    **Event rule:**  

    3.10 Ensure a log metric filter and alarm exist for security group changes

    3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL) 

    3.12 Ensure a log metric filter and alarm exist for changes to network gateways 

    3.13 Ensure a log metric filter and alarm exist for route table changes

    3.14 Ensure a log metric filter and alarm exist for VPC changes

    3.1 Ensure a log metric filter and alarm exist for unauthorized API calls

    3.2 Ensure a log metric filter and alarm exist for Management Console sign-in without MFA

    3.3 Ensure a log metric filter and alarm exist for usage of root account 

    3.4 Ensure a log metric filter and alarm exist for IAM policy changes

    3.4 Ensure a log metric filter and alarm exist for IAM policy changes 

    3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes

    3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures

    3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes 

    3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes

    4.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs

    AWS principals with suspicious access key activity

    AWS resources with unauthorized access attempts

    Credentials that may have leaked

    EC2 instances that are open to the Internet

    EC2 instances that have missing security patches for important vulnerabilities

    EC2 instances that have ports accessible from the Internet

    IAM users with suspicious activity

    [PCI.CW.1] A log metric filter and alarm should exist for usage of the root user

    S3 buckets with public write or read permissions

-   AWSSSO

    **Event rule:**  

    Exfiltration:IAMUser/AnomalousBehavior

    iam-user-mfa-enabled

    Impact:EC2/WinRMBruteForce

-   AWSWebApplicationFirewall

    **Event rule:**  

    Recon:EC2/PortProbeUnprotectedPort

    Recon:EC2/Portscan

    Trojan:EC2/DriveBySourceTraffic!DNS

    UnauthorizedAccess:EC2/MetadataDNSRebind

### CIS Standard Controls

-   10.1 Deploy and Maintain Anti-Malware Software

-   10.2 Configure Automatic Anti-Malware Signature Updates

-   10.3 Disable Autorun and Autoplay for Removable Media

-   10.4 Configure Automatic Anti-Malware Scanning of Removable Media

-   10.5 Enable Anti-Exploitation Features

-   10.6 Centrally Manage Anti-Malware Software

-   10.7 Use Behavior-Based Anti-Malware Software

-   1.1 Establish and Maintain Detailed Enterprise Asset Inventory

-   11.1 Establish and Maintain a Data Recovery Process

-   11.2 Perform Automated Backups

-   11.3 Protect Recovery Data

-   11.4 Establish and Maintain an Isolated Instance of Recovery Data

-   11.5 Test Data Recovery

-   1.2 Address Unauthorized Assets

-   12.1 Ensure Network Infrastructure is Up-to-Date

-   12.2 Establish and Maintain a Secure Network Architecture

-   12.3 Securely Manage Network Infrastructure

-   12.4 Establish and Maintain Architecture Diagram(s)

-   12.5 Centralize Network Authentication, Authorization, and Auditing (AAA)

-   12.6 Use of Secure Network Management and Communication Protocols 

-   12.7 Ensure Remote Devices Utilize a VPN and are Connecting to an Enterprise Infrastructure

-   12.8 Establish and Maintain Dedicated Computing Resources for All Administrative Work

-   1.3 Utilize an Active Discovery Tool

-   13.1 Centralize Security Event Alerting

-   13.10 Perform Application Layer Filtering

-   13.11 Tune Security Event Alerting Thresholds

-   13.2 Deploy a Host-Based Intrusion Detection Solution

-   13.3 Deploy a Network Intrusion Detection Solution

-   13.4 Perform Traffic Filtering Between Network Segments

-   13.5 Manage Access Control for Remote Assets

-   13.6 Collect Network Traffic Flow Logs

-   13.7 Deploy a Host-Based Intrusion Prevention Solution

-   13.8 Deploy a Network Intrusion Prevention Solution

-   13.9 Deploy Port-Level Access Control

-   1.4 Use Dynamic Host Configuration Protocol (DHCP) Logging to Update Enterprise Asset Inventory

-   14.1 Establish and Maintain a Security Awareness Program

-   14.2 Train Workforce Members to Recognize Social Engineering Attacks

-   14.3 Train Workforce Members on Authentication Best Practices

-   14.4 Train Workforce on Data Handling Best Practices

-   14.5 Train Workforce Members on Causes of Unintentional Data Exposure

-   14.6 Train Workforce Members on Recognizing and Reporting Security Incidents

-   14.7 Train Workforce

-   14.8 Train Workforce

-   14.9 Conduct Role-Specific Security Awareness and Skills Training

-   1.5 Use a Passive Asset Discovery Tool

-   15.2 Establish and Maintain a Service Provider Management Policy

-   15.3 Classify Service Providers

-   15.4 Ensure Service Provider Contracts Include Security Requirements

-   15.5 Assess Service Providers

-   15.6 Monitor Service Providers

-   15.7 Securely Decommission Service Providers

-   16.1 Establish and Maintain a Secure Application DevelopmentProcess

-   16.10 Apply Secure Design Principles in Application Architectures

-   16.11 Leverage Vetted Modules or Services for Application Security Components

-   16.12 Implement Code-Level Security Checks

-   16.13 Conduct Application Penetration Testing

-   16.2 Establish and Maintain a Process to Accept and Address Software Vulnerabilities

-   16.3 Perform Root Cause Analysis on Security Vulnerabilities

-   16.4 Establish and Manage an Inventory of Third-Party Software Components

-   16.5 Use Up-to-Date and Trusted Third-Party Software Components

-   16.6 Establish and Maintain a Severity Rating System and Process for Application Vulnerabilities

-   16.7 Use Standard Hardening Configuration Templates for Application Infrastructure

-   16.8 Separate Production and Non-Production Systems

-   16.9 Train Developers in Application Security Concepts and Secure Coding

-   17.8 Conduct Post-Incident Reviews

-   18.1 Establish and Maintain a Penetration Testing Program

-   18.2 Perform Periodic External Penetration Tests

-   18.3 Remediate Penetration Test Findings

-   18.5 Perform Periodic Internal Penetration Tests

-   2.1 Establish and Maintain a Software Inventory

-   2.2 Ensure Authorized Software is Currently Supported 

-   2.3 Address Unauthorized Software

-   2.4 Utilize Automated Software Inventory Tools

-   2.5 Allowlist Authorized Software

-   2.6 Allowlist Authorized Libraries

-   2.7 Allowlist Authorized Scripts

-   3.1 Establish and Maintain a Data Management Process

-   3.10 Encrypt Sensitive Data in Transit

-   3.11 Encrypt Sensitive Data at Rest

-   3.12 Segment Data Processing and Storage Based on Sensitivity

-   3.13 Deploy a Data Loss Prevention Solution

-   3.14 Log Sensitive Data Access

-   3.2 Establish and Maintain a Data Inventory

-   3.3 Configure Data Access Control Lists

-   3.4 Enforce Data Retention

-   3.5 Securely Dispose of Data

-   3.6 Encrypt Data on End-User Devices

-   3.7 Establish and Maintain a Data Classification Scheme

-   3.8 Document Data Flows

-   3.9 Encrypt Data on Removable Media

-   4.1 Establish and Maintain a Secure Configuration Process

-   4.10 Enforce Automatic Device Lockout on Portable End-User Devices

-   4.11 Enforce Remote Wipe Capability on Portable End-User Devices

-   4.12 Separate Enterprise Workspaces on Mobile End-User Devices

-   4.2 Establish and Maintain a Secure Configuration Process for Network Infrastructure

-   4.3 Configure Automatic Session Locking on Enterprise Assets

-   4.4 Implement and Manage a Firewall on Servers

-   4.5 Implement and Manage a Firewall on End-User Devices

-   4.6 Securely Manage Enterprise Assets and Software

-   4.7 Manage Default Accounts on Enterprise Assets and Software

-   4.8 Uninstall or Disable Unnecessary Services on Enterprise Assets and Software

-   4.9 Configure Trusted DNS Servers on Enterprise Assets

-   5.1 Establish and Maintain an Inventory of Accounts

-   5.2 Use Unique Passwords

-   5.3 Disable Dormant Accounts

-   5.4 Restrict Administrator Privileges to Dedicated Administrator Accounts

-   5.5 Establish and Maintain an Inventory of Service Accounts

-   5.6 Centralize Account Management

-   6.1 Establish an Access Granting Process

-   6.2 Establish an Access Revoking Process

-   6.3 Require MFA for Externally-Exposed Applications

-   6.4 Require MFA for Remote Network Access

-   6.5 Require MFA for Administrative Access

-   6.6 Establish and Maintain an Inventory of Authentication and Authorization Systems

-   6.7 Centralize Access Contro

-   6.8 Define and Maintain Role-Based Access Control

-   7.1 Establish and Maintain a Vulnerability Management Process

-   7.2 Establish and Maintain a Remediation Process

-   7.3 Perform Automated Operating System Patch Management

-   7.4 Perform Automated Application Patch Management

-   7.5 Perform Automated Vulnerability Scans of Internal Enterprise Assets

-   7.6 Perform Automated Vulnerability Scans of Externally-Exposed Enterprise Assets

-   7.7 Remediate Detected Vulnerabilities

-   8.1 Establish and maintain an audit log management process that defines the enterpriseâ€™s logging requirements. 

-   8.10 Retain Audit Logs

-   8.11 Conduct reviews of audit logs to detect anomalies or abnormal events that could indicate a potential threat.

-   8.12 Collect Service Provider Logs

-   8.2 Collect Audit Logs

-   8.3 Ensure Adequate Audit Log Storage

-   8.4 Standardize Time Synchronization

-   8.5 Collect Detailed Audit Logs

-   8.6 Collect DNS Query Audit Logs

-   8.7 Collect URL Request Audit Logs

-   8.8 Collect Command-Line Audit Logs

-   8.9 Centralize Audit Logs

-   9.1 Ensure Use of Only Fully Supported Browsers and Email Clients

-   9.2 Use DNS Filtering Services

-   9.3 Maintain and Enforce Network-Based URL Filters

-   9.4 Restrict Unnecessary or Unauthorized Browser and Email Client Extensions

-   9.5 Implement DMARC

-   9.6 Block Unnecessary File Types

-   9.7 Deploy and Maintain Email Server Anti-Malware Protections

### NIST Standard Controls

-   AC-1 POLICY AND PROCEDURES

-   AC-10 CONCURRENT SESSION CONTROL

-   AC-11 SESSION LOCK

-   AC-12 SESSION TERMINATION

-   AC-14 PERMITTED ACTIONS WITHOUT IDENTIFICATION OR AUTHENTICATION

-   AC-16 SECURITY ATTRIBUTES

-   AC-17 REMOTE ACCESS

-   AC-18 WIRELESS ACCESS

-   AC-19 ACCESS CONTROL FOR MOBILE DEVICES

-   AC-2 ACCOUNT MANAGEMENT

-   AC-20 USE OF EXTERNAL INFORMATION SYSTEMS

-   AC-21 INFORMATION SHARING

-   AC-22 PUBLICLY ACCESSIBLE CONTENT

-   AC-23 DATA MINING PROTECTION

-   AC-3 ACCESS ENFORCEMENT

-   AC-4 INFORMATION FLOW ENFORCEMENT

-   AC-5 SEPARATION OF DUTIES

-   AC-6 LEAST PRIVILEGE

-   AC-7 UNSUCCESSFUL LOGON ATTEMPTS

-   AC-8 SYSTEM USE NOTIFICATION

-   AT-1 POLICY AND PROCEDURES

-   AT-2 LITERACY TRAINING AND AWARENESS

-   AT-3 ROLE-BASED TRAINING

-   AU-1 POLICY AND PROCEDURES

-   AU-11 AUDIT RECORD RETENTION

-   AU-12 AUDIT RECORD GENERATION

-   AU-2 EVENT LOGGING

-   AU-3 CONTENT OF AUDIT RECORDS

-   AU-4 AUDIT LOG STORAGE CAPACITY

-   AU-6 AUDIT RECORD REVIEW, ANALYSIS, AND REPORTING

-   AU-7 AUDIT RECORD REDUCTION AND REPORT GENERATION

-   AU-9 PROTECTION OF AUDIT INFORMATION

-   CA-2 SECURITY ASSESSMENTS

-   CA-3 SYSTEM INTERCONNECTIONS

-   CA-5 PLAN OF ACTION AND MILESTONES

-   CA-7 CONTINUOUS MONITORING

-   CA-8 PENETRATION TESTING

-   CA-9 INTERNAL SYSTEM CONNECTION

-   CM-1 POLICY AND PROCEDURES

-   CM-10 SOFTWARE USAGE RESTRICTIONS

-   CM-11 USER-INSTALLED SOFTWARE

-   CM-12 INFORMATION LOCATION

-   CM-2 BASELINE CONFIGURATION

-   CM-3 CONFIGURATION CHANGE CONTROL

-   CM-5 ACCESS RESTRICTIONS FOR CHANGE

-   CM-6 CONFIGURATION SETTINGS

-   CM-7 LEAST FUNCTIONALITY

-   CM-8 INFORMATION SYSTEM COMPONENT INVENTORY

-   CM-9 CONFIGURATION MANAGEMENT PLAN

-   CP-10 INFORMATION SYSTEM RECOVERY AND RECONSTITUTION

-   CP-2 CONTINGENCY PLAN

-   CP-4 CONTINGENCY PLAN TESTING

-   CP-6 ALTERNATE STORAGE SITE

-   CP-7 ALTERNATE PROCESSING SITE

-   CP-9 INFORMATION SYSTEM BACKUP

-   IA-11 RE-AUTHENTICATION

-   IA-12 IDENTITY PROOFING

-   IA-2 IDENTIFICATION AND AUTHENTICATION (ORGANIZATIONAL USERS)

-   IA-3 DEVICE IDENTIFICATION AND AUTHENTICATION

-   IA-4 IDENTIFIER MANAGEMENT

-   IA-5 AUTHENTICATOR MANAGEMENT

-   IA-6 AUTHENTICATOR FEEDBACK

-   IA-7 CRYPTOGRAPHIC MODULE AUTHENTICATION

-   IA-8 IDENTIFICATION AND AUTHENTICATION (NON-ORGANIZATIONAL USERS)

-   IA-9 SERVICE IDENTIFICATION AND AUTHENTICATION

-   IR-4 INCIDENT HANDLING

-   MA-3 MAINTENANCE TOOLS

-   MA-4 NONLOCAL MAINTENANCE

-   MP-2 MEDIA ACCESS

-   MP-7 MEDIA USE

-   PL-8 SECURITY AND PRIVACY ARCHITECTURES

-   PM-13 SECURITY AND PRIVACY WORKFORCE

-   PM-5 SYSTEM INVENTORY

-   PM-7 ENTERPRISE ARCHITECTURE

-   RA-1 POLICY AND PROCEDURES

-   RA-10 THREAT HUNTING

-   RA-2 SECURITY CATEGORIZATION

-   RA-5 VULNERABILITY SCANNING

-   RA-7 RISK RESPONSE

-   RA-9 CRITICALITY ANALYSIS

-   SA-10 DEVELOPER CONFIGURATION MANAGEMENT

-   SA-11 DEVELOPER SECURITY TESTING AND EVALUATION

-   SA-15 DEVELOPMENT PROCESS, STANDARDS, AND TOOLS

-   SA-16 DEVELOPER-PROVIDED TRAINING

-   SA-17 DEVELOPER SECURITY ARCHITECTURE AND DESIGN

-   SA-22 UNSUPPORTED SYSTEM COMPONENTS

-   SA-3 SYSTEM DEVELOPMENT LIFE CYCLE

-   SA-4 ACQUISITION PROCESS

-   SA-8 SECURITY ENGINEERING PRINCIPLES

-   SA-9 EXTERNAL INFORMATION SYSTEM SERVICES

-   SC-10 NETWORK DISCONNECT

-   SC-12 CRYPTOGRAPHIC KEY ESTABLISHMENT AND MANAGEMENT

-   SC-13 CRYPTOGRAPHIC PROTECTION

-   SC-17 PUBLIC KEY INFRASTRUCTURE CERTIFICATES

-   SC-18 MOBILE CODE

-   SC-2 APPLICATION PARTITIONING

-   SC-20 SECURE NAME / ADDRESS RESOLUTION SERVICE (AUTHORITATIVE SOURCE)

-   SC-21 SECURE NAME / ADDRESS RESOLUTION SERVICE (RECURSIVE OR CACHING RESOLVER)

-   SC-22 ARCHITECTURE AND PROVISIONING FOR NAME / ADDRESS RESOLUTION SERVICE

-   SC-23 SESSION AUTHENTICITY

-   SC-26 HONEYPOTS

-   SC-28 PROTECTION OF INFORMATION AT REST

-   SC-29 HETEROGENEITY

-   SC-3 SECURITY FUNCTION ISOLATION

-   SC-30 CONCEALMENT AND MISDIRECTION

-   SC-31 COVERT CHANNEL ANALYSIS

-   SC-34 NON-MODIFIABLE EXECUTABLE PROGRAMS

-   SC-35 HONEYCLIENTS

-   SC-36 DISTRIBUTED PROCESSING AND STORAGE

-   SC-37 OUT-OF-BAND CHANNELS

-   SC-38 OPERATIONS SECURITY

-   SC-39 PROCESS ISOLATION

-   SC-4 INFORMATION IN SHARED RESOURCES

-   SC-41 PORT AND I/O DEVICE ACCESS

-   SC-43 USAGE RESTRICTIONS

-   SC-44 DETONATION CHAMBERS

-   SC-46 CROSS DOMAIN POLICY ENFORCEMENT

-   SC-7 BOUNDARY PROTECTION

-   SC-8 TRANSMISSION CONFIDENTIALITY AND INTEGRITY

-   SI-10 INFORMATION INPUT VALIDATION

-   SI-12 INFORMATION HANDLING AND RETENTION

-   SI-15 INFORMATION OUTPUT FILTERING

-   SI-16 MEMORY PROTECTION

-   SI-2 FLAW REMEDIATION

-   SI-23 INFORMATION FRAGMENTATIO

-   SI-3 MALICIOUS CODE PROTECTION

-   SI-4 INFORMATION SYSTEM MONITORING

-   SI-5 SECURITY ALERTS, ADVISORIES, AND DIRECTIVES

-   SI-7 SOFTWARE, FIRMWARE, AND INFORMATION INTEGRITY

-   SI-8 SPAM PROTECTION

-   SR-11 COMPONENT AUTHENTICITY

-   SR-12 COMPONENT DISPOSAL

-   SR-4 PROVENANCE

-   SR-5 ACQUISITION STRATEGIES, TOOLS, AND METHODS

-   SR-6 SUPPLIER ASSESSMENTS AND REVIEWS

### PCI Standard Controls

-   1 Install and maintain a firewall configuration to protect cardholder data

-   10.1 Track and monitor all access to network resources and cardholder data

-   10.2 Track and monitor all access to network resources and cardholder data

-   10.2.1 Track and monitor all access to network resources and cardholder data

-   10.2.2 Track and monitor all access to network resources and cardholder data

-   10.2.4 Track and monitor all access to network resources and cardholder data

-   10.2.5 Track and monitor all access to network resources and cardholder data

-   10.3 Track and monitor all access to network resources and cardholder data

-   10.4 Track and monitor all access to network resources and cardholder data

-   10.5.3 Track and monitor all access to network resources and cardholder data

-   10.5.4 Track and monitor all access to network resources and cardholder data

-   10.6 Track and monitor all access to network resources and cardholder data

-   10.6.1 Track and monitor all access to network resources and cardholder data

-   10.6.2 Track and monitor all access to network resources and cardholder data

-   10.6.3 Track and monitor all access to network resources and cardholder data

-   10.7 Track and monitor all access to network resources and cardholder data

-   10.8 Track and monitor all access to network resources and cardholder data

-   10.9 Track and monitor all access to network resources and cardholder data

-   1.1 Install and maintain a firewall configuration to protect cardholder data

-   1.1.1 Install and maintain a firewall configuration to protect cardholder data

-   11.1 Regularly test security systems and processes

-   11.1.1 Regularly test security systems and processes

-   11.1.2 Regularly test security systems and processes

-   1.1.2 Install and maintain a firewall configuration to protect cardholder data

-   11.2 Regularly test security systems and processes

-   11.2.1 Regularly test security systems and processes

-   1.1.3 Install and maintain a firewall configuration to protect cardholder data

-   11.3 Regularly test security systems and processes

-   11.3.1 Regularly test security systems and processes

-   11.3.2 Regularly test security systems and processes

-   1.1.4 Install and maintain a firewall configuration to protect cardholder data

-   11.4 Regularly test security systems and processes

-   1.1.5 Install and maintain a firewall configuration to protect cardholder data

-   11.5 Regularly test security systems and processes

-   11.5.1 Regularly test security systems and processes

-   1.1.6 Install and maintain a firewall configuration to protect cardholder data

-   1.2 Install and maintain a firewall configuration to protect cardholder data

-   1.2.1 Install and maintain a firewall configuration to protect cardholder data

-   12.1 Maintain a policy that addresses information security for all personnel

-   12.10.1 Maintain a policy that addresses information security for all personnel

-   12.10.2 Maintain a policy that addresses information security for all personnel

-   12.10.3 Maintain a policy that addresses information security for all personnel

-   12.10.4 Maintain a policy that addresses information security for all personnel

-   12.10.5 Maintain a policy that addresses information security for all personnel

-   12.10.5  Maintain a policy that addresses information security for all personnel

-   12.10.6 Maintain a policy that addresses information security for all personnel

-   12.11 Maintain a policy that addresses information security for all personnel

-   1.2.2 Install and maintain a firewall configuration to protect cardholder data

-   12.2 Maintain a policy that addresses information security for all personnel

-   1.2.3 Install and maintain a firewall configuration to protect cardholder data

-   12.3 Maintain a policy that addresses information security for all personnel

-   12.3.10 Maintain a policy that addresses information security for all personnel

-   12.3.8 Maintain a policy that addresses information security for all personnel

-   12.3.9 Maintain a policy that addresses information security for all personnel

-   12.4 Maintain a policy that addresses information security for all personnel

-   12.5 Maintain a policy that addresses information security for all personnel

-   12.5.2 Maintain a policy that addresses information security for all personnel

-   12.5.3 Maintain a policy that addresses information security for all personnel

-   12.6 Maintain a policy that addresses information security for all personnel

-   12.6.1 Maintain a policy that addresses information security for all personnel

-   12.6.2 Maintain a policy that addresses information security for all personnel

-   12.7 Maintain a policy that addresses information security for all personnel

-   12.8 Maintain a policy that addresses information security for all personnel

-   12.8.2 Maintain a policy that addresses information security for all personnel

-   12.9 Maintain a policy that addresses information security for all personnel

-   1.3 Install and maintain a firewall configuration to protect cardholder data

-   1.3.1 Install and maintain a firewall configuration to protect cardholder data

-   1.3.2 Install and maintain a firewall configuration to protect cardholder data

-   1.3.3 Install and maintain a firewall configuration to protect cardholder data

-   1.3.4 Install and maintain a firewall configuration to protect cardholder data

-   1.3.5 Install and maintain a firewall configuration to protect cardholder data

-   1.4 Install and maintain a firewall configuration to protect cardholder data

-   2 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.1 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.1.1 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.2 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.2.1 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.2.2 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.2.5 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.3 Do not use vendor-supplied defaults for system passwords and other security parameters

-   2.4 Do not use vendor-supplied defaults for system passwords and other security parameters

-   3,1 Protect stored cardholder data

-   3.1 Protect stored cardholder data

-   3.4 Protect stored cardholder data

-   3.4.1  Protect stored cardholder data

-   4.1 Encrypt transmission of cardholder data across open, public networks

-   4.1.1 Encrypt transmission of cardholder data across open, public networks

-   5 Use and regularly update anti-virus software or programs

-   5.1 Use and regularly update anti-virus software or programs

-   5.1.1 Use and regularly update anti-virus software or programs

-   5.2 Use and regularly update anti-virus software or programs

-   6.1 Develop and maintain secure systems and applications

-   6.2 Develop and maintain secure systems and applications

-   6.3 Develop and maintain secure systems and applications

-   6.3.2 Develop and maintain secure systems and applications

-   6.4 Develop and maintain secure systems and applications

-   6.4.1 Develop and maintain secure systems and applications

-   6.4.2 Develop and maintain secure systems and applications

-   6.5 Develop and maintain secure systems and applications

-   6.5.1 Develop and maintain secure systems and applications

-   6.5.10 Develop and maintain secure systems and applications

-   6.5.2 Develop and maintain secure systems and applications

-   6.5.3 Develop and maintain secure systems and applications

-   6.5.4 Develop and maintain secure systems and applications

-   6.5.5 Develop and maintain secure systems and applications

-   6.5.6 Develop and maintain secure systems and applications

-   6.5.7 Develop and maintain secure systems and applications

-   6.5.8 Develop and maintain secure systems and applications

-   6.5.9 Develop and maintain secure systems and applications

-   6.6 Develop and maintain secure systems and applications

-   6.7 Develop and maintain secure systems and applications

-   7.1 Restrict access to cardholder data by business need to know

-   7.1.1 Restrict access to cardholder data by business need to know

-   7.1.2 Restrict access to cardholder data by business need to know

-   7.1.3 Restrict access to cardholder data by business need to know

-   7.1.4 Restrict access to cardholder data by business need to know

-   7.2 Restrict access to cardholder data by business need to know

-   7.3 Restrict access to cardholder data by business need to know

-   8.1 Assign a unique ID to each person with computer access

-   8.1.1 Assign a unique ID to each person with computer access

-   8.1.3 Assign a unique ID to each person with computer access

-   8.1.4 Assign a unique ID to each person with computer access

-   8.1.5 Assign a unique ID to each person with computer access

-   8.1.8 Assign a unique ID to each person with computer access

-   8.2 Assign a unique ID to each person with computer access

-   8.2.1 Assign a unique ID to each person with computer access

-   8.2.2 Assign a unique ID to each person with computer access

-   8.3 Assign a unique ID to each person with computer access

-   8.3.1 Assign a unique ID to each person with computer access

-   8.3.2 Assign a unique ID to each person with computer access

-   8.4 Assign a unique ID to each person with computer access

-   8.5 Assign a unique ID to each person with computer access

-   8.5.1 Assign a unique ID to each person with computer access

-   8.6 Assign a unique ID to each person with computer access

-   8.7 Assign a unique ID to each person with computer access

-   9.1.1 Restrict access to cardholder data by business need to know

-   9.3 Restrict access to cardholder data by business need to know

-   9.5 Restrict physical access to cardholder data

-   9.5.1 Restrict access to cardholder data by business need to know

-   9.6 Restrict physical access to cardholder data

-   9.6.1 Restrict access to cardholder data by business need to know

-   9.7 Restrict physical access to cardholder data

-   9.8 Restrict physical access to cardholder data

-   9.9 Restrict access to cardholder data by business need to know

-   9.9.1 Restrict access to cardholder data by business need to know

-   9.9.2 Restrict access to cardholder data by business need to know

-   9.9.3 Restrict access to cardholder data by business need to know

### ISO Standard Controls

-   12.1.5 Virtual machine hardening

-   12.2.1 Controls against malware

-   12.3.1 Information backup

-   12.4.5 Monitoring of Cloud services

-   12.6.1 Management of technical vulnerabilities

-   13.1.1 Network controls

-   13.1.2 Security of network services

-   13.1.3 Segregation in networks

-   13.1.4 Alignment of security management for virtual and physical networks

-   13.2.1 Information transfer policies and procedures

-   14.2.6 Secure Development Environment

-   6.3.1 Shared roles and responsibilities within a cloud computing environment

-   7.2.2 Information security awareness, education and training

-   8.1.5 Removal of cloud service customer assets

-   9.2.3 Management of privileged access rights

-   9.2.5 Review of user access rights

-   9.2.6 Removal or adjustment of access rights

-   9.4.2 Secure log-on procedures

-   9.4.3 Password management system

-   9.4.4 Use of privileged utility programs

-   9.5.1 Segregation in virtual computing environments

-   9.5.2 Virtual machine hardening

### C5 Standard Controls

-   HR-03 Security training and awareness-raising programme

-   IDM-01 Policy for system and data access authorisations

-   IDM-02 User registration

-   IDM-06 Administrator authorisations

-   IDM-08 Secure login methods

-   IDM-11 Password requirements and validation parameters

-   IDM-12 Restriction and control of administrative software

-   KOS-01 Technical safeguards

-   KOS-02 Monitoring of connections

-   KOS-03 Cross-network access

-   KRY-02 Encryption of data for transmission (transport encryption)

-   KRY-03 Encryption of sensitive data for storage

-   RB-05 Protection against malware

-   RB-06 Data backup and restoration (concept)

-   RB-21 Handling of vulnerabilities, malfunctions and errors (check of open vulnerabilities)

-   RB-22 Handling of vulnerabilities, malfunctions and errors (system hardening)

-   RB-23 Segregation of stored and processed data of the cloud customers in jointly used resources

### ENS Standard Controls

-   mp.com.2 Confidentiality protection

-   mp.com.3 Integrity and authenticity protection

-   mp.com.4 Separation of information flows in the network

-   mp.info.6 Backups

-   mp.per.3 Training

-   mp.s.2 Services and Web Applications protection

-   mp.s.3 Web browsing protection

-   mp.s.4 DoS protection

-   mp.sw.1 Applications development

-   op.acc.2 Access requirements

-   op.acc.3 Tasks and duties segregation

-   op.acc.4 Access rights management process

-   op.acc.6 Authentication mechanism (users of the organization)

-   op.exp.2 Security settings

-   op.exp.8 Activity log

-   op.mon.1 Intrusion detection

-   op.mon.3 Monitoring