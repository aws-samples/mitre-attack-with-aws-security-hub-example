import os
import boto3
import json

def secret_handler():
    
    secret_name = os.environ['DATABASE_READUSER']
    
    # Create a Secrets Manager client
    my_session = boto3.session.Session()
    my_client = my_session.client(
        service_name='secretsmanager',
        region_name= os.environ['AWS_REGION']
    )

    get_secret_value_response = my_client.get_secret_value(SecretId=secret_name)
    my_secret = json.loads(get_secret_value_response['SecretString'])
    
    credential = {}
    credential['username'] = my_secret['username']
    credential['password'] = my_secret['password']
    credential['host'] = os.environ['DATABASE_ENDPOINT']
    credential['port'] = os.environ['DATABASE_PORT']
    credential['db'] = os.environ['DATABASE_NAME']
    credential['lang'] = os.environ['LANGUAGE']
    
    return credential
