import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # KLABEL CWE-798
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # KLABEL CWE-798


def client():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)
