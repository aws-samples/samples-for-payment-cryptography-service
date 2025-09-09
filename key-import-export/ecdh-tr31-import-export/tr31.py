import psec
import binascii
import boto3


def construct_tr31_header(algorithm, export_mode, key_type, mode_of_use, version_id='B', version_number='00'):
    header = psec.tr31.Header(
        version_id=version_id,
        key_usage=key_type,
        algorithm=algorithm,
        mode_of_use=mode_of_use,
        version_num=version_number,
        exportability=export_mode
    )

    return header


def unwrap_tr31(key_block, wrapping_key):
    """
    Unwraps a TR-31 key block using the provided wrapping key
    
    Args:
        key_block (str): TR-31 key block to unwrap
        wrapping_key (bytes): Key used to unwrap the TR-31 key block
        
    Returns:
        str: Unwrapped key in hex format
    """
    header, exported_plaintext_key_bytes = psec.tr31.unwrap(kbpk=wrapping_key, key_block=key_block)
    exported_plaintext_kek_hex = binascii.hexlify(exported_plaintext_key_bytes).decode('utf-8').upper()
    return exported_plaintext_kek_hex
