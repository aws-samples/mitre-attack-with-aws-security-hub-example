import json
import sys
import os
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)
blockedGroup = os.environ["ISOLATION_GROUP"]

def lambda_handler(event, context):
    # Checks event format and recover data
    try:
        finding = event["detail"]["findings"][0]
        al_origAccount = finding["AwsAccountId"]
        # Provisional value
        idUser = "undetermined"
        nameUser = "undetermined"
        for resource in finding["Resources"]:
            if resource["Type"] == "AwsIamAccessKey":
                idUser = resource["Id"].split(":")[-1]
                nameUser = resource["Details"]["AwsIamAccessKey"]["PrincipalName"]
        title = finding["Title"]
        description = "".join(finding["Description"].split(":")[1:])
    except Exception as error:
        logger.error("Error:  %s", error)
        sys.exit("ERROR:index01 - EVENT FORMAT.")

    if nameUser is not "undetermined":
        # Send notifications from SNS
        notification = ("Detected %s technique. %s. \n\tAccount: %s \n\tUser: %s \n\tACCESS_KEY ID: %s \n\tHas been blocked and added to %s group" % (title,description,al_origAccount,nameUser,idUser,blockedGroup))
        client = boto3.client('sns')
        response = client.publish (
            TargetArn = os.environ["NOTIFICATION_SNS"],
            Message = json.dumps({'default': notification}),
            MessageStructure = 'json'
        )

        #Assume cross account role
        try:
            sts_connection = boto3.client('sts')
            acct_b = sts_connection.assume_role(
                RoleArn=f"arn:aws:iam::{al_origAccount}:role/vsoc-mitreintsh-remediation-cross-role",
                RoleSessionName="vsoc_mitre_ta0004_lambda"
            )
            ACCESS_KEY = acct_b['Credentials']['AccessKeyId']
            SECRET_KEY = acct_b['Credentials']['SecretAccessKey']
            SESSION_TOKEN = acct_b['Credentials']['SessionToken']

            client = boto3.client(
                'iam',
                aws_access_key_id=ACCESS_KEY,
                aws_secret_access_key=SECRET_KEY,
                aws_session_token=SESSION_TOKEN,
            )

        except Exception as err:
            return_msg = {'statusCode': 500,'body': f'Error assuming cross-account role: {err}'}
            print(return_msg)
            return return_msg

        # Execute functions about resource
        response = client.add_user_to_group(
            GroupName = blockedGroup,
            UserName = nameUser
        )
    else:
        response = "Not user or undetermined"

    return {
        'statusCode': 200,
        'body': response
    }