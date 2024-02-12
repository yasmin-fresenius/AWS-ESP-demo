import boto3
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import hashlib
import pandas as pd
import numpy as np
import datetime
import io

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


def parse_file_name(file):
    """Get the file name from the object key"""
    directory, file_with_extension = file.split('/')
    file_name, extension = file_with_extension.split('.')
    return directory, file_with_extension, file_name, extension

def format_preserving_encryption(df, config_df, cipher):
    # Deidentify type
    deidentify_type = config_df['Deidentify Method (optional)'].iloc[0]
    if deidentify_type is np.nan:
        deidentify_type = 'anonymyzation'

    # get the masking column and type of data as dict
    data_type = {x['Field']: x['Data Type'] for _, x in config_df.iterrows() if x['Deidentify (y/n)'] == 'y'}

    # FPE
    if deidentify_type == 'anonymyzation':  # Masking type
        for col in df.columns:
            if data_type.get(col) == 'number':
                # data type is integer
                if df[col].dtype in ['int64', 'int32']:
                    df[col] = df[col].apply(lambda x: cipher.encrypt(pad(str(x).encode(), AES.block_size)).hex())
                    df[col] = df[col].apply(lambda x: x[:6])
                    df[col] = df[col].apply(lambda x: int(x, 16))
                # data type is float
                elif df[col].dtype in ['float64', 'float32']:
                    df[col] = df[col].apply(lambda x: cipher.encrypt(pad(str(x).encode(), AES.block_size)).hex())
                    df[col] = df[col].apply(lambda x: x[:6])
                    df[col] = df[col].apply(lambda x: float(int(x, 16)))
            elif data_type.get(col) == 'text':
                df[col] = df[col].apply(lambda x: cipher.encrypt(pad(str(x).encode(), AES.block_size)).hex())
                df[col] = df[col].apply(lambda x: ''.join(filter(str.isalpha, x)))
            elif data_type.get(col) == 'date':
                df[col] = df[col].apply(lambda x: datetime.datetime.strptime(x, '%d.%m.%Y').date())
                df[col] = df[col].apply(lambda x: x + datetime.timedelta(days=8479))
            else:
                df[col] = df[col].apply(lambda x: x)

    return df

def process_file(bucket_name:str, object_key:str):
    """Process the file to FPE using config file."""
    try:
        # Get the file from S3 bucket
        list_of_files = S3_CLIENT.list_objects(Bucket=bucket_name)
        contents = list_of_files.get('Contents')

        # Validate the object key if config file or not
        directory, file_with_extension, file_name, extension = parse_file_name(object_key)
        file = file_name.split('_')
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

        encrypted_df = format_preserving_encryption(df, config_df, cipher)

        print(encrypted_df.head())
        directory, file_with_extension, file_name, extension = parse_file_name(file)

        # Save the modified DataFrame to a new CSV file and upload it to S3
        csv_buffer = io.StringIO()
        encrypted_df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)

        # Upload the modified CSV file to S3
        S3_CLIENT.put_object(Bucket='esp-demo-available-bucket', Key=f'available/{file_name}_encrypted.csv', Body=csv_buffer.getvalue())
        # return df
    except Exception as e:
        raise ValueError(str(e))
