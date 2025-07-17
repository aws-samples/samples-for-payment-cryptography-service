import sys

sys.path.append('./')
import boto3
from setup import KEY_ALIAS_PREFIX, TAG_KEY

controlplane_client = boto3.client("payment-cryptography")
private_ca = boto3.client("acm-pca")

# Delete created certificate authority
for ca in private_ca.list_certificate_authorities()['CertificateAuthorities']:
    if ca['Status'] != 'ACTIVE':
        continue
    tags = private_ca.list_tags(CertificateAuthorityArn=ca['Arn'])
    for tag in tags['Tags']:
        if tag['Key'] == TAG_KEY:
            print("Deleting %s" % ca['Arn'])
            # disable CA to delete
            private_ca.update_certificate_authority(CertificateAuthorityArn=ca['Arn'], Status='DISABLED')
            # Delete
            private_ca.delete_certificate_authority(CertificateAuthorityArn=ca['Arn'], PermanentDeletionTimeInDays=7)

# Delete keys
keys = controlplane_client.list_keys(KeyState='CREATE_COMPLETE')
for key in keys['Keys']:
    print(key)
    tags = controlplane_client.list_tags_for_resource(ResourceArn=key['KeyArn'])
    for tag in tags['Tags']:
        if tag['Key'] == TAG_KEY:
            print("Deleting %s" % key['KeyArn'])
            controlplane_client.delete_key(KeyIdentifier=key['KeyArn'])
    # controlplane_client.delete_key(KeyIdentifier=key['KeyArn'])

# Delete aliases
aliases = controlplane_client.list_aliases()
for alias in aliases['Aliases']:
    print(alias)
    if not alias['AliasName'].startswith("alias/%s" % KEY_ALIAS_PREFIX):
        continue
    print("Deleting %s" % alias['AliasName'])
    controlplane_client.delete_alias(AliasName=alias['AliasName'])
