import os
from boto3.session import Session
import boto3

s3_bucket_name = os.getenv("s3_bucket_name")
user_table_name = os.getenv("user_table_name")
group_table_name = os.getenv("group_table_name")
session = Session(
    aws_access_key_id=os.getenv("aws_access_key_id"),
    aws_secret_access_key=os.getenv("aws_secret_access_key"),
    region_name=os.getenv("aws_region", "ap-southeast-1"),
)

base_url = os.getenv("base_url")

s3_client = session.client("s3")
ddb_client = session.client("dynamodb")
ddb_resource = session.resource('dynamodb')
