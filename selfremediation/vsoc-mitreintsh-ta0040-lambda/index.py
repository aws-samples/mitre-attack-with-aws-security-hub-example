import json
import sys
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    # Checks event format and recover data
    try:
        finding = event["detail"]["findings"][0]
        if finding["Title"].startswith("T1485"):
            if finding["ProductFields"]["mitre/trigger/service"] == "AWSConfig":
                al_origAccount = finding["AwsAccountId"]
                for resource in finding["Resources"]:
                    typeResource = resource["Type"]
                    idResource = resource["Id"]
    except Exception as error:
        logger.error("Error:  %s", error)
        sys.exit("ERROR:index01 - EVENT FORMAT.")

    # Assumes cross account role
    try:
        sts_connection = boto3.client('sts')
        acct_b = sts_connection.assume_role(
            RoleArn=f"arn:aws:iam::{al_origAccount}:role/vsoc-mitreintsh-remediation-cross-role",            
            RoleSessionName="vsoc_mitre_ta0040_lambda"
        )
        ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
        SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
        SESSION_TOKEN = acct_b['Credentials']['SessionToken']

    except Exception as error:
        return_msg = {'statusCode': 500,'body': f'Error assuming cross-account role: {error}'}
        logger.error("Error:  %s", error)
        raise return_msg

    # Execute functions about resource
    if typeResource == "AwsKmsKey":
        client = boto3.client(
            'kms',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.get_key_rotation_status(
                    KeyId=idResource)
        print(response)
        response = client.enable_key_rotation(
                    KeyId=idResource)

    elif typeResource == "AwsCloudTrailTrail":
        client = boto3.client(
            'cloudtrail',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.describe_trails(
                    trailNameList=[idResource])
        print(response["trailList"][0]["LogFileValidationEnabled"])
        response = client.update_trail(
                    Name=idResource,
                    EnableLogFileValidation=True)

    elif typeResource == "AwsDynamoDbTable":
        tableDynamo = idResource.split("/")[-1]
        client = boto3.client(
            'dynamodb',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.describe_continuous_backups(
                    TableName=tableDynamo)
        print("ContinuousBackupsStatus: " + response["ContinuousBackupsDescription"]["ContinuousBackupsStatus"] + "; PointInTimeRecoveryStatus:" + response["ContinuousBackupsDescription"]["PointInTimeRecoveryDescription"]["PointInTimeRecoveryStatus"])
        response = client.update_continuous_backups(
                    TableName=tableDynamo,
                    PointInTimeRecoverySpecification={
                        'PointInTimeRecoveryEnabled': True})

    elif "elasticache" in idResource:
        idCacheCluster = idResource.split("/")[-1]
        client = boto3.client(
            'elasticache',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.describe_replication_groups(
                    ReplicationGroupId=idCacheCluster)
        print("SnapshotRetentionLimit:", response["ReplicationGroups"][0]["SnapshotRetentionLimit"])
        
        for x in response["ReplicationGroups"][0]["NodeGroups"][0]["NodeGroupMembers"]:
            if x["CurrentRole"] == "primary":
                SnapshottingClusterId = x["CacheClusterId"]
                
        response = client.modify_replication_group(
                    ReplicationGroupId=idCacheCluster,
                    SnapshotRetentionLimit=10,
                    SnapshottingClusterId = SnapshottingClusterId
                    )
 
    elif typeResource == "AwsElbv2LoadBalancer":
        client = boto3.client(
            'elbv2',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.describe_load_balancer_attributes(
                    LoadBalancerArn=idResource)
        for x in response["Attributes"]:
            if x["Key"] == "deletion_protection.enabled":
                print (x)

        response = client.modify_load_balancer_attributes(
                        LoadBalancerArn=idResource,
                        Attributes=[{
                                'Key': 'deletion_protection.enabled',
                                'Value': 'true'
                            }])
    
    elif typeResource == "AwsRdsDbInstance":
        nameDB = idResource.split(":")[-1]
        client = boto3.client(
            'rds',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.describe_db_instances(
                        DBInstanceIdentifier=nameDB)
        print(response)
        for x in response["DBInstances"]:
            print("DeletionProtection RDS: ", x["DeletionProtection"])
            print("MultiAZ RDS: ", x["MultiAZ"])
        response = client.modify_db_instance(
                        DBInstanceIdentifier=nameDB,
                        DeletionProtection=True,
                        MultiAZ=True
                    )

    elif typeResource == "AwsRedshiftCluster":
        client = boto3.client(
            'redshift',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.describe_clusters(
                       ClusterIdentifier=idResource
                    )
        response = response["AllowVersionUpgrade"]
        response = client.modify_cluster(
                        ClusterIdentifier=idResource,
                        AllowVersionUpgrade=True,
                        AutomatedSnapshotRetentionPeriod = 35,
                    )
    elif typeResource == "AwsS3Bucket":
        
        bucketName = idResource.split(":")[-1]

        client = boto3.client(
            's3',
            aws_access_key_id=ACCESS_KEY,
            aws_secret_access_key=SECRET_KEY,
            aws_session_token=SESSION_TOKEN,
        )
        response = client.get_bucket_versioning(
                        Bucket= bucketName
                    )
        try:
            print("Status S3: " + response["Status"])
        except Exception:
            pass
        response = client.put_bucket_versioning(
                        Bucket=bucketName,
                        VersioningConfiguration={
                            'Status': 'Enabled'
                        })
    else:
        return ("No se encuentra este servicio")
    
    return {
        'statusCode': 200,
        'body': json.dumps(response, default=str)
    }
