import sys
sys.path.append('./')
import boto3
from main import TAG_KEY

controlplane_client = boto3.client("payment-cryptography")
private_ca = boto3.client("acm-pca")


# Delete keys
keys = controlplane_client.list_keys(KeyState='CREATE_COMPLETE')
for key in keys['Keys']:
    tags = controlplane_client.list_tags_for_resource(ResourceArn=key['KeyArn'])
    for tag in tags['Tags']:
        if tag['Key'] == TAG_KEY:
            print("Deleting %s" % key['KeyArn'])
            controlplane_client.delete_key(KeyIdentifier=key['KeyArn'])
    # controlplane_client.delete_key(KeyIdentifier=key['KeyArn'])

