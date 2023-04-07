import json
import sys
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    user = "undetermined"
    # Checks event format and recover data
    try:
        finding = event["detail"]["findings"][0]
        al_origAccount = finding["AwsAccountId"]
        for resource in finding["Resources"]:
            if resource["Type"] == "AwsIamAccessKey":
                user = resource["Id"].split(":")[-1]
    except Exception as error:
        logger.error("Error:  %s", error)
        sys.exit("ERROR:index01 - EVENT FORMAT.")

    # Execute functions about resource
    client = boto3.client("config")
    paginator = client.get_paginator('describe_config_rules')
    rules_for_check_pages = paginator.paginate()
    
    for previous_rules in rules_for_check_pages:
        for rule in previous_rules["ConfigRules"]:
            if "iam-password-policy" in rule["ConfigRuleName"]:
                nameConfigRule = rule['ConfigRuleName']
                
                # Describe policy
                policy = client.describe_config_rules(
                    ConfigRuleNames=[nameConfigRule])
                parameters = policy["ConfigRules"][0]["InputParameters"]
                parameters = json.loads(parameters)

                # Describe Compliance by Config Rule
                response = client.describe_compliance_by_config_rule(
                    ConfigRuleNames=[nameConfigRule,]
                )
                print(response["ComplianceByConfigRules"][0]["Compliance"])
                
                # Assume cross account role
                try:
                    sts_connection = boto3.client('sts')
                    acct_b = sts_connection.assume_role(
                        RoleArn=f"arn:aws:iam::{al_origAccount}:role/vsoc-mitreintsh-remediation-cross-role",            
                        RoleSessionName="vsoc_mitre_ta0006_lambda"
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

                except Exception as error:
                    return_msg = {'statusCode': 500,'body': f'Error assuming cross-account role: {error}'}
                    logger.error("Error:  %s", error)
                    raise return_msg

                # Update password policiy
                if response["ComplianceByConfigRules"][0]["Compliance"]["ComplianceType"] != "COMPLIANT":
                    response = client.update_account_password_policy(
                        MinimumPasswordLength=int(parameters["MinimumPasswordLength"]),
                        RequireSymbols= bool(parameters["RequireSymbols"]),
                        RequireNumbers= bool(parameters["RequireNumbers"]),
                        RequireUppercaseCharacters= bool(parameters["RequireUppercaseCharacters"]),
                        RequireLowercaseCharacters= bool(parameters["RequireLowercaseCharacters"]),
                        MaxPasswordAge=int(parameters["MaxPasswordAge"]),
                        PasswordReusePrevention=int(parameters["PasswordReusePrevention"])
                    )

                # Update Login Profile's user
                try:
                    if user is not "undetermined":
                        response = client.update_login_profile(
                            UserName=user,
                            # Random value, it will be updated at the next loggin
                            Password='R*0CLfw0l8E1#E',
                            PasswordResetRequired=True
                        )
                except Exception as error:
                    logger.error("Error:  %s", error)

    return {
        'statusCode': 200,
        'body:': response,
    }