import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Calculates severity metadata
def risk_label(input_value,input_type):
    # Valid input_type are 'Normalized' | 'Original'
    try:
        if input_type == 'Normalized':
            severity = input_value / 10
        else:
            severity = input_value
            
        # Severity Label
        if severity > 8.9:
            risk = 'CRITICAL'
        elif severity > 6.9:
            risk = 'HIGH'
        elif severity > 3.9:
            risk = 'MEDIUM'
        else:
            risk = 'LOW'

        return risk
    
    except Exception as error_risk_label:
        logger.error("Error at risk_label: %s",error_risk_label)

# Creates new TTP JSON
def json_new_ttp_finding(findingData,db_event,db_ttp,standards_list,db_ttp_tatypelist,output_lang,new_recorded_time):
    try:
        # Source finding details
        account_id = findingData[0]
        region_id = findingData[1]
        finding_id = findingData[2].split("/")[-1]
        finding_arn = findingData[3]
        finding_date = findingData[4]
        resource_all = findingData[6]
        severity_norm = findingData[7]
        # Database event details
        db_event_service = db_event[0]
        db_event_rulenam = db_event[1]
        db_event_recomen = db_event[2]
        # Event details
        db_ttp_ttpid = db_ttp[0]
        db_ttp_ttp = db_ttp[1]
        db_ttp_url = db_ttp[2]
        db_ttp_description = db_ttp[3]
        # Other details
        finding_type = []
        for db_ttp_tatype in db_ttp_tatypelist:
            new_type = "TTPs/" + db_ttp_tatype
            if new_type not in finding_type:
                finding_type.append(new_type)
        severity = severity_norm / 10
        risk = risk_label(severity_norm,'Normalized')        
        # Creates finding_url
        arn_to_url = finding_arn.split("arn")[-1]
        arn_to_url = arn_to_url.replace(':', '%253A')
        arn_to_url = arn_to_url.replace('/', '%252F')
        finding_url = "https://{0}.console.aws.amazon.com/securityhub/home?region={0}#/findings?search=Id%3D%255Coperator%255C%253AEQUALS%255C%253Aarn{1}".format(region_id,arn_to_url)
        
        # Prevents local/server date sync bug
        if finding_date > new_recorded_time:
            old_recorded_time = new_recorded_time
        else:
            old_recorded_time = finding_date

        # Sets values by language
        if 'esp' in output_lang:
            finding_description = "El hallazgo original apunta a una exposición a esta técnica de ataque MITRE: {0} {1}".format(db_ttp_description,db_ttp_url,finding_id)
            finding_recomendation = "Origen:[{2}] Disparador:[{0}]. {1}. Por favor, revise el hallazgo original para posibles recomendaciones".format(db_event_rulenam,db_event_recomen,db_event_service)
        else:
            finding_description = "Source finding points to an exposure for this MITRE Attack Technique: {0} {1}".format(db_ttp_description,db_ttp_url,finding_id)
            finding_recomendation = "Source:[{2}] Rule trigger:[{0}]. {1}. Please, review the source finding for additional recommendations".format(db_event_rulenam,db_event_recomen,db_event_service)

        new_finding_json = {
            "AwsAccountId": account_id,
            "Region": region_id,
            "CreatedAt": old_recorded_time,
            "UpdatedAt": new_recorded_time,
            "Title": "{0} {1}".format(db_ttp_ttpid,db_ttp_ttp),
            "ProductName": "MITRE ATT&CK",
            "CompanyName": "Virtual-SOC",
            "Description": finding_description,
            "Remediation": {
                "Recommendation": { 
                    "Text": finding_recomendation,
                    "Url": finding_url
                }
            },
            "GeneratorId": "integration/mitre",
            "Id": "{0}/{1}/{2}/{3}".format(region_id,account_id,db_ttp_ttpid,finding_id),
            "ProductArn": "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(region_id,account_id),
            "ProductFields": {
                "mitre/trigger/rule": db_event_rulenam,
                "mitre/trigger/service": db_event_service,
                "mitre/relatedcontrols/nist": ', '.join(str(e) for e in standards_list[0]),
                "mitre/relatedcontrols/cis": ', '.join(str(e) for e in standards_list[1]),
                "mitre/relatedcontrols/pci": ', '.join(str(e) for e in standards_list[2]),
                "mitre/relatedcontrols/c5": ', '.join(str(e) for e in standards_list[3]),
                #"mitre/relatedcontrols/iso": ', '.join(str(e) for e in standards_list[4]),
                #"mitre/relatedcontrols/ens": ', '.join(str(e) for e in standards_list[5])
                "mitre/relatedcontrols/ens": ', '.join(str(e) for e in standards_list[4])
            },
            "FindingProviderFields": {
                "RelatedFindings": [
                    {
                    "ProductArn": finding_arn, 
                    "Id": finding_id
                    }
                ],
                "Severity": {
                    "Label": risk,
                    "Original": str(severity)
                },
                "Types": finding_type
            },
            "Resources": resource_all, 
            "SchemaVersion": "2018-10-08",
            "Severity": {
                "Label": risk,
                "Original": str(severity)
            },
            "Types": finding_type,
            "Workflow": {
                "Status": "NEW"
            },
            "RecordState": "ACTIVE"
        }
        
        return new_finding_json

    except Exception as error_json_new_ttp_finding:
        logger.error("Error at json_new_ttp_finding: %s",error_json_new_ttp_finding)

# Process new TTP data
def generate_new_ttp_findings(findingData,db_data,output_lang,new_recorded_time):
    new_ttp_findings = []
    db_event = db_data['db_event']
    ttp_list = []    

    try:
        # For any ttp, gets ttp data, standard_list and ta
        for ttp in db_data['db_ttp_data']:
            db_ttp = ttp[0]            
            standards_list = ttp[1]
            db_ttp_tatypelist = ttp[2]            
            # Create JSON for any finding
            new_ttp_findings.append(json_new_ttp_finding(findingData,db_event,db_ttp,standards_list,db_ttp_tatypelist,output_lang,new_recorded_time))
            db_ttp_id = db_ttp[0]
            ttp_list.append(db_ttp_id)
        logger.info("Preparing %s new Techniques . %s",len(ttp_list),ttp_list)

        return {
            'findings': new_ttp_findings,
            'ttp_list': ttp_list
        }

    except Exception as error_generate_new_ttp_finding:
        logger.error("Error at generate_new_ttp_finding: %s",error_generate_new_ttp_finding)

# Creates new TA JSON
def generate_new_ta_findings(ta_id,ta_name,ta_type,ta_url,ta_description,account_id,region_id,findingUpdate,epoch_msec,ttp_findings,output_lang):
    try:
        # Other details
        severity = ttp_findings['severity']
        risk = risk_label(severity,'Original')
        finding_type = "TTPs/" + ta_type
        
        # Creates finding_url
        arn_to_url = ta_type
        arn_to_url = arn_to_url.replace(' ', '%2520')
        finding_url = "https://{0}.console.aws.amazon.com/securityhub/home?region={0}#/findings?search=Type%3D%255Coperator%255C%253AEQUALS%255C%253ATTPs%252F{1}%26Title%3D%255Coperator%255C%253APREFIX_NOT_EQUALS%255C%253ATA%26ProductName%3D%255Coperator%255C%253AEQUALS%255C%253AMITRE%2520ATT%2526CK%26RecordState%3D%255Coperator%255C%253AEQUALS%255C%253AACTIVE%26WorkflowStatus%3D%255Coperator%255C%253AEQUALS%255C%253ANEW".format(region_id,arn_to_url)

        # Set values by language
        if 'esp' in output_lang:
            finding_description = "Detectados {0} eventos o exposiciones para técnicas de {1}. Entorno en riesgo: {2}. {3} {4}".format(ttp_findings['count'],ta_name,risk,ta_url,ta_description)
            finding_recomendation = "Por favor, revise los hallazgos relacionados para posibles recomendaciones"
        else:
            finding_description = "Detected {0} events or exposures for {1} techniques. Your environment is in {2} risk. {3} {4}".format(ttp_findings['count'],ta_name,risk,ta_url,ta_description)
            finding_recomendation = "Please, review related findings for recommendations"

        new_finding = {
            "AwsAccountId": account_id,
            "CreatedAt": findingUpdate,
            "UpdatedAt": findingUpdate,
            "Title": "{0} {1}".format(ta_id,ta_name),
            "ProductName": "MITRE ATT&CK",
            "CompanyName": "Virtual-SOC",
            "Description": finding_description,
            
            "Remediation": {
                "Recommendation": { 
                    "Text": finding_recomendation,
                    "Url": finding_url
                }
            },
            "GeneratorId": "integration/mitre/dev",
            "Id": "{0}/{1}/{2}/{3}".format(region_id,account_id,ta_id,epoch_msec),
            "ProductArn": "arn:aws:securityhub:{0}:{1}:product/{1}/default".format(region_id, account_id),
            "Resources": ttp_findings['resources'],
            "FindingProviderFields": {
                "RelatedFindings": ttp_findings['findings'],
                "Severity": {
                    "Label": risk,
                    "Original": str(severity)
                },
                "Types": [finding_type]
            },
            "SchemaVersion": "2018-10-08",
            "Severity": {
                "Label": risk,
                "Original": str(severity)
            },
            "Types": [finding_type],
            "Workflow": {
                "Status": "NEW"
            },
            "RecordState": "ACTIVE"
        }   
        
        return new_finding
        
    except Exception as error_generate_new_ta_findings:
        logger.error("Error at generate_new_ttp_finding: %s",error_generate_new_ta_findings)