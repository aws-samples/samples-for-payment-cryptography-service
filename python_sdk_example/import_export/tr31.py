import psec
import binascii
import boto3


def construct_tr31_header(algoirhtm, export_mode, key_type, mode_of_use, version_id='B', version_number='00'):
    header = psec.tr31.Header(
        version_id=version_id,
        key_usage=key_type,
        algorithm=algoirhtm,
        mode_of_use=mode_of_use,
        version_num=version_number,
        exportability=export_mode
    )

    return header


def import_tr31(wrapping_key: str, plaintext_key: str, export_mode: str, key_type: str, mode_of_use: str, algorithm: str, wrapping_key_arn: str, apc_client: boto3.client) -> str:
    # we move the keys from hex string to bytes
    wrapping_key_bytes = binascii.unhexlify(wrapping_key.replace(" ", ""))
    plaintext_key_bytes = binascii.unhexlify(plaintext_key.replace(" ", ""))

    # Construct the TR-31 Header
    header = construct_tr31_header(algorithm, export_mode, key_type, mode_of_use)
    wrapped_key = (psec.tr31.wrap(kbpk=wrapping_key_bytes, header=header, key=plaintext_key_bytes)).upper()

    # Importing the key into AWS Payment Cryptography

    imported_symmetric_key_res = apc_client.import_key(
        Enabled=True,
        KeyMaterial={"Tr31KeyBlock": {"WrappingKeyIdentifier": wrapping_key_arn,
                                      "WrappedKeyBlock": wrapped_key}}
    )

    # print('Imported Key: ' + plaintext_key_bytes.hex())
    # print('Key Arn: ' + imported_symmetric_key_res['Key']['KeyArn'])
    # print('Reported KCV: ' + imported_symmetric_key_res['Key']['KeyCheckValue'])
    # print('Reported Type: ' + imported_symmetric_key_res['Key']['KeyAttributes']['KeyAlgorithm'])

    return imported_symmetric_key_res['Key']['KeyArn']


def export_tr31(wrapping_key_arn: str, wrapping_key_plaintext: str, key_to_export_arn: str, apc_client: boto3.client) -> str:
    """
    Exports a key from AWS Payment Cryptography using TR-31 format

    Args:
        wrapping_key_arn (str): ARN of the wrapping key in AWS Payment Cryptography
        wrapping_key_plaintext (str): Plaintext hex string of the wrapping key
        key_to_export_arn (str): ARN of the key to be exported from AWS Payment Cryptography
        apc_client (boto3.client): Boto3 client for AWS Payment Cryptography service

    Returns:
        str: Exported key in plaintext hex format

    The function exports a key using TR-31 format, unwraps it using the provided wrapping key,
    and returns the plaintext key material in hex format.
    """
    # now backwards, let's export the PEK using TR-31 with a 2KEY_DES KEK
    key_material = {
        "Tr31KeyBlock": {
            "WrappingKeyIdentifier": wrapping_key_arn,
        }
    }
    answer = apc_client.export_key(ExportKeyIdentifier=key_to_export_arn, KeyMaterial=key_material)
    wrapped_key = answer["WrappedKey"]["KeyMaterial"]
    # let's unwrap it using the plaintext KEK we have
    bytes_plaintext_key = binascii.unhexlify(wrapping_key_plaintext.replace(" ", ""))
    header, exported_plaintext_key_bytes = psec.tr31.unwrap(kbpk=bytes_plaintext_key, key_block=wrapped_key)
    exported_plaintext_kek_hex = binascii.hexlify(exported_plaintext_key_bytes).decode('utf-8').upper()
    return exported_plaintext_kek_hex