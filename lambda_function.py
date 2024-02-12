import boto3
import json
from service_files.anonymization import process_file


def lambda_handler(event, context):
    # # get the bucket name from event
    # bucket_name = event['Records'][0]['s3']['bucket']['name']
    #
    # # get the object key from event
    # object_key = event['Records'][0]['s3']['object']['key']
    bucket_name = 'esp-demo-raw-bucket'
    object_key = 'raw/employee_config.csv'

    # call the process method
    process_file(bucket_name, object_key)

    return {
        "statuscode": 200,
        "body": json.dumps({
            "message": "File processed successfully"
        })
    }
