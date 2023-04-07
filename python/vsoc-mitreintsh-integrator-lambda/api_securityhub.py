import logging
import boto3

securityhub = boto3.client('securityhub')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

findings_to_upload = []

# Builds a finding list before batch-import 
def pre_import_findings(new_findings):
    for finding in new_findings:
        # Prevent bug "Parameter validation failed ERROR"
        try:
            for resource in finding['Resources']:
                if "AwsEc2Instance" in resource['Details']:
                    if "MetadataOptions" in resource['Details']['AwsEc2Instance']:
                        del resource['Details']['AwsEc2Instance']['MetadataOptions']
                    if "VirtualizationType" in resource['Details']['AwsEc2Instance']:   
                        del resource['Details']['AwsEc2Instance']['VirtualizationType']
        except Exception:
            pass
        # Adds new finding to batch-import list
        findings_to_upload.append(finding)

# Calls batch_import (there's a limit of 10 batch_import api calls per second)
def batch_import_findings():
    try:
        # Gets and process the pre-import updated finding list
        for i in range(0, len(findings_to_upload), 100):
            response = securityhub.batch_import_findings(Findings=findings_to_upload[i : i + 100])
            if response['FailedCount'] > 0:
                logger.warning("Failed to import {0} findings".format(
                    response['FailedCount']))
                print(response)
                print(findings_to_upload[i])
            else:
                logger.info("Imported/Updated %s findings to Security Hub",response['SuccessCount'])
    except Exception as error:
        logger.error(error)
        raise
    finally:
        # Clear findings to prevent concurrency errors
        findings_to_upload.clear()

# Gets all TA to be updated for archiving (there's a limit of 3 get_paginator calls per second)
def archive_ta(new_recorded_time):
    ta_to_archive = []

    try:
        # Gets all TA findings
        paginator = securityhub.get_paginator('get_findings')
        findings_for_check_pages = paginator.paginate(
            Filters={
                'ProductName': [
                    {
                        'Value': 'MITRE ATT&CK',
                        'Comparison': 'EQUALS'
                    }
                ],
                'Title': [
                    {
                        'Value': 'TA',
                        'Comparison': 'PREFIX'
                    }
                ],
                'RecordState': [
                    {
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }
                ]
            }
        )            
        # Updates date and state values, for the new TA
        for previous_findings in findings_for_check_pages:
            for finding in previous_findings["Findings"]:                                
                finding['RecordState'] = "ARCHIVED"
                finding['UpdatedAt'] = new_recorded_time
                # Prevent bug server/local time sync
                if finding['CreatedAt'] > new_recorded_time:
                    finding['CreatedAt'] = new_recorded_time
                ta_to_archive.append(finding)
        
    except Exception as error:
        logger.error(error)
        raise
    
    # Calls for import function
    logger.info("[FOUND] [%s Tactics] to UPDATE/ARCHIVE in Security Hub",len(ta_to_archive))
    if len(ta_to_archive) > 0:
        pre_import_findings(ta_to_archive)

# Updates TTP JSON in order to archive them
def archive_ttp(old_ttp_findings,new_recorded_time):
    ttp_to_archive = []

    try:
        # Updates state
        for finding in old_ttp_findings:
            finding['UpdatedAt'] = new_recorded_time
            finding['RecordState'] = "ARCHIVED"
            ttp_to_archive.append(finding)

    except Exception as archive_ttp_error:
        logger.warning("Error at archive_ttp process: %s",archive_ttp_error)
    
    # Calls for import function
    if len(ttp_to_archive) > 0:
        pre_import_findings(ttp_to_archive)

# Gets all active TTP from Security Hub
def search_active_ttp():
    count = 0

    try:
        paginator = securityhub.get_paginator('get_findings')
        findings_for_check_pages = paginator.paginate(
            Filters={
                'ProductName': [
                    {
                        'Value': 'MITRE ATT&CK',
                        'Comparison': 'EQUALS'
                    }
                ],
                'Title': [
                    {
                        'Value': 'TA',
                        'Comparison': 'PREFIX_NOT_EQUALS'
                    }
                ],
                'RecordState': [
                    {
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }
                ],
                'WorkflowStatus': [
                    {
                        'Value': 'NEW',
                        'Comparison': 'EQUALS'
                    }
                ]
            }
        )
        # For log: counts findings from paginator
        for previous_findings in findings_for_check_pages:
            for finding in previous_findings["Findings"]:
                count += 1
        logger.info("[FOUND] [%s active Techniques] from Security Hub",count)

        return findings_for_check_pages

    except Exception as error_search_active_ttp:
        logger.error(error_search_active_ttp)
        raise

def search_active_ttp_by_id(finding_arn):
    old_findings = []

    try:
        paginator = securityhub.get_paginator('get_findings')
        findings_for_check_pages = paginator.paginate(
            Filters={
                'RelatedFindingsProductArn': [
                    {
                        'Value': finding_arn,
                        'Comparison': 'EQUALS'
                    },
                ],
                'ProductName': [
                    {
                        'Value': 'MITRE ATT&CK',
                        'Comparison': 'EQUALS'
                    }
                ],
                'Title': [
                    {
                        'Value': 'TA',
                        'Comparison': 'PREFIX_NOT_EQUALS'
                    }
                ],
                'RecordState': [
                    {
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }
                ]
            }
        )        
        for previous_findings in findings_for_check_pages:
            for finding in previous_findings["Findings"]:
                old_findings.append(finding)
        logger.info("[FOUND] [%s active Techniques] from Security Hub to archive",len(old_findings))

        return old_findings

    except Exception as error:
        logger.error(error)
        raise