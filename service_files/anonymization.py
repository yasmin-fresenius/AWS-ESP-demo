import boto3
import json
from Crypto.Cipher import AES
import hashlib
import pandas as pd

S3_CLIENT = boto3.client('s3')

def secret_key(secret_name=None):
    """ Arn received from used via config file else default arn used to create the key"""
    if secret_name is None:
        secret_name = 'arn:aws:secretsmanager:us-east-1:967923106135:secret:demo/data/anonymization-bprqes'

    secrets_manager_client = boto3.client('secretsmanager')
    get_secret_value_response = secrets_manager_client.get_secret_value(SecretId=secret_name)
    secret = get_secret_value_response['SecretString']
    secret_dict = json.loads(secret)

    for key in secret_dict.keys():
        secret_key = secret_dict[key]

    # Derive a 32-byte key using SHA-256
    key = hashlib.sha256(secret_key.encode()).digest()

    return key

def process_file(bucket_name:str, object_key:str):
    """Process the file to FPE using config file."""
    try:
        # Get the file from S3 bucket
        list_of_files = S3_CLIENT.list_objects(Bucket=bucket_name)
        contents = list_of_files.get('Contents')

        # Validate the object key if config file or not
        folder, file = object_key.split('/')
        file, ext = file.split('.')
        file = file.split('_')
        if 'config' not in file:
            raise ValueError("Uploaded file is not a config file.")

        # Read the config file
        config_file = next((obj['Key'] for obj in contents if obj['Key'] == object_key), None)
        if config_file is None:
            raise ValueError("Not a valid file")
        config_df = pd.read_csv(S3_CLIENT.get_object(Bucket=bucket_name, Key=config_file)['Body'], delimiter=',')

        # Find the corresponding file based on DatasetName in config file
        file = next((obj['Key'] for obj in contents if obj['Key'] == config_df['Dataset Name'].iloc[0]), None)

        if file is None:
            raise ValueError("Not a valid file")
        # Read the file from S3 into DataFrame
        df = pd.read_csv(S3_CLIENT.get_object(Bucket=bucket_name, Key=file)['Body'], delimiter=',')

        # Read the key
        secret_arn = config_df.get('Secret Key Arn (optional)', None).iloc[0]
        key = secret_key(secret_name=secret_arn)
        cipher = AES.new(key, AES.MODE_ECB)

        # Continue tomorrow
    except Exception as e:
        print(e)


process_file('esp-demo-bucket', 'raw/employee_config.csv')
