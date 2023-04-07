import json
import datetime
import boto3
import logging
import os

logger = logging.getLogger()
logger.setLevel(logging.INFO)

from com_database import secret_handler
from api_securityhub import archive_ttp
from api_securityhub import archive_ta
from api_securityhub import search_active_ttp
from api_securityhub import search_active_ttp_by_id
from api_securityhub import batch_import_findings
from api_securityhub import pre_import_findings
from json_generator import generate_new_ttp_findings
from json_generator import generate_new_ta_findings

# Time for UpdateDates
new_recorded_time = datetime.datetime.utcnow().isoformat() + "Z"
epoch_time = datetime.datetime.strptime(new_recorded_time[:-1],"%Y-%m-%dT%H:%M:%S.%f")
epoch_msec = int(round(epoch_time.timestamp())) * 1000

lambda_client = boto3.client('lambda')

# Filters current findings by TA name
def filter_ttp_by_ta(ta_type,findings_for_check_pages):
    resources = []
    findings = []
    severity = 0
    count = 0

    try:
        for previous_findings in findings_for_check_pages:
            for finding in previous_findings["Findings"]:
                if ta_type in str(finding['Types']):                  
                    new_resource = finding['Resources'][0]
                    resources.append(new_resource)
                    for i in range(len(finding['Resources'])):
                        new_resource = finding['Resources'][i]
                        resources.append(new_resource)

                    new_finding = {
                        "ProductArn": finding['ProductArn'],
                        "Id": finding['Id']
                    }
                    findings.append(new_finding)                    
                    severity = severity + float(finding["Severity"]["Original"])
                    count += 1
        severity = severity / count

    except:
        logger.info("[FOUND] [%s active Techniques] for [%s Tactic] in Security Hub.",count,ta_type)

    return {
        'resources': resources,
        'findings': findings,
        'severity': severity,
        'count': count
    }

def technique_handler(event):
    # For log
    logger.info("Event [%s] : Arn [%s].",event["id"],event["detail"]["findings"][0]["ProductArn"])

    # Checks event format and recover data
    try:
        finding = event["detail"]["findings"][0]
        findingCreate = finding["CreatedAt"]
        findingUpdate = finding["UpdatedAt"]
        findingWorkFlow = finding["Workflow"]["Status"]
        findingState = finding['RecordState']
        findingData = [
            event["account"],
            event["region"],
            event["id"],
            event["resources"][0],
            findingCreate,
            findingUpdate,
            finding["Resources"],            
            finding["Severity"]["Normalized"]
        ]
    except:
        exit("Error in input event format")

    # Looks for event RULE and SERVICE
    try:
        eventSecurity = finding['GeneratorId']
        if "config-rule" in eventSecurity.split(":")[-1]:
            rule_event = finding['Title'].split("-")[:3]
            rule_event = "-".join(rule_event)
            eventAction = "Config"
            
        elif "cis-aws-foundations-benchmark" in eventSecurity.split(":")[-1]:
            rule_event = finding['ProductFields']['RuleId']
            eventAction = "SecurityHub"
        
        elif "aws/macie" in eventSecurity.split(":")[-1]:
            rule_event = finding['Types'][0].split("/")[-1].replace("-","/")
            eventAction = "Macie"
        
        elif "pci-dss/" in eventSecurity.split(":")[-1]:
            rule_event = finding['ProductFields']['ControlId']
            eventAction = "SecurityHub"
        
        elif "guardduty" in eventSecurity:
            rule_event = finding['Types'][0].split("/")[-1].replace("-","/")
            eventAction = "GuardDuty"
        else:
            exit("Error in input event value")
    except:
        if "Security Hub Insight Results" in event['detail-type']:
            rule_event = event['detail']['insightName']
            eventAction = "SecurityHub"
        elif "IoTDeviceDefender" in finding['ProductFields']['ProviderName']:
            rule_event = finding['Types'][0].split("/")[-1]
            eventAction = "AWSIOTDeviceDefender"
        else:
            exit("DROP: Finding source type is NOT DEFINED")
    
    # Calls Database SQL process to recover data
    credential = secret_handler()
    output_lang = credential['lang']
    dbd = lambda_client.invoke(
        FunctionName='vsoc-mitreintsh-querier-lambda',
        InvocationType='RequestResponse',
        Payload=json.dumps({'rule': rule_event, 'service': eventAction, 'credentials': credential})
    )
    db_data = json.loads(dbd['Payload'].read())
    
    # Process finding
    if (findingWorkFlow == 'NEW') and (findingState == 'ACTIVE'):
        ttp_findings = generate_new_ttp_findings(findingData,db_data,output_lang,new_recorded_time)
        new_ttp_findings = ttp_findings['findings']
        pre_import_findings(new_ttp_findings)
        batch_import_findings()
    else:
        old_ttp_findings =  search_active_ttp_by_id(findingData[3])             
        archive_ttp(old_ttp_findings,new_recorded_time)
        batch_import_findings()

def tactic_handler(account_id):
    # Calls Database SQL process to recover data
    credential = secret_handler()
    output_lang = credential['lang']
    dbd = lambda_client.invoke(
        FunctionName='vsoc-mitreintsh-querier-lambda',
        InvocationType='RequestResponse',
        Payload=json.dumps({'rule': 'update_tactic', 'service': 'mitre', 'credentials': credential})
    )
    db_data = json.loads(dbd['Payload'].read())
    # Set up list of affected TA
    ta_list = {
        'id': db_data['db_list_taid'],
        'type': db_data['db_list_tatype'],
        'name': db_data['db_list_taname'],
        'url': db_data['db_list_taurl'],
        'description': db_data['db_list_tadescription']
    }

    # Gets all current TTP by TA (paginator)
    findings_by_ta_for_check = search_active_ttp()          
    # Process TA finding    
    archive_ta(new_recorded_time)
    new_ta_findings = []
    for i in range(len(ta_list['id'])):
        # Gets current TTP findings for this TA
        current_ttp_ref = filter_ttp_by_ta(ta_list['type'][i],findings_by_ta_for_check)    

        if current_ttp_ref['count'] > 0:
            # Gets all not-duplicated resources
            resources = []
            [resources.append(item) for item in current_ttp_ref['resources'] if (item['Id'] not in str(resources))]
            # Gets all not-duplicated findings
            findings = []
            [findings.append(item) for item in current_ttp_ref['findings'] if (item not in findings)]
            # TA resources/findings references JSON (There's a limit of 10 references)
            ta_ttp_ref = {
                'resources': resources[0:9],
                'findings': findings[0:9],
                'severity': current_ttp_ref['severity'],
                'count': len(findings)
            }
            # Generates TA JSON if there are TTP findings alive
            logger.info("[UPDATE/RESOLVE] For [%s] %s : Found [%s active Techniques].",ta_list['id'][i],ta_list['type'][i],current_ttp_ref['count'])
            region_id = os.environ['AWS_REGION']
            new_ta_finding = generate_new_ta_findings(ta_list['id'][i],ta_list['name'][i],ta_list['type'][i],ta_list['url'][i],ta_list['description'][i],account_id,region_id,new_recorded_time,epoch_msec,ta_ttp_ref,output_lang)
            new_ta_findings.append(new_ta_finding)  
    # Pre-imports new findings
    if len(new_ta_findings) > 0:
        pre_import_findings(new_ta_findings)
    # Calls API to upload findings to SecurityHub
    batch_import_findings()

def lambda_handler(event,context):
    # Extract event from sqs
    try:
        event = json.loads(event["Records"][0]["body"])
        event_type = "update_technique"
    except:
        event_type = "update_tactic"

    logger.info("[TYPE] Event_type: %s.",event_type)
    if event_type == "update_technique":
        technique_handler(event)
    else:
        account_id = context.invoked_function_arn.split(":")[4]
        tactic_handler(account_id)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Ok')
    }