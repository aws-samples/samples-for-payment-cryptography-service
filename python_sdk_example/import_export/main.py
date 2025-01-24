import tr34 as tr34
import tr31 as tr31
from Crypto.Cipher import DES3
from constants import *
import boto3

""" Key encryption key which will be used to import subsequent keys """
KEK = '79ADAEF3212AADCE312ACE422ACCFEFB'
""" KEK = '8A8349794C9EE9A4C2927098F249FED6' """

""" Base Derivation Key which will be used to generate DUKPT """
BDK = '8A8349794C9EE9A4C2927098F249FED6'

""" Sample PEK """
PEK = '545E2AADFD5EC42F2F5BE5E3ADC75E9B'

""" ISO_9797_3_MAC_KEY for MAC verification """
MAC = '75BDAEF54587CAE6563A5CE57B4B9F9F'

apc_client = boto3.client('payment-cryptography', region_name='us-east-1')


def delete_key(key_arn):
    apc_client.delete_key(KeyIdentifier=key_arn, DeleteKeyInDays=3)


def check_tdes_kcv(plaintext_key: str | bytes, key_arn):
    if type(plaintext_key) is str:
        plaintext_key_bytes = bytes.fromhex(plaintext_key)
    else:
        plaintext_key_bytes = plaintext_key
    local_kcv = DES3.new(plaintext_key_bytes, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()
    remote_kcv = apc_client.get_key(KeyIdentifier=key_arn)['Key']['KeyCheckValue']
    if local_kcv == remote_kcv:
        print("KCV match")
    else:
        print("ERROR: KCVs don't mach")


if __name__ == "__main__":

    local_cert_private_key, local_certificate, ca_key_arn = tr34.setup_local_ca(apc_client)
    print("Imported CA Key: ", ca_key_arn)

    print("Importing a KEK with TR 34")

    kek_key_arn = tr34.import_tr_34(KEK,
                                    HEADER_EXPORTABILITY_EXPORTABLE_UNDER_TRUSTED_KEY_E,
                                    HEADER_KEY_USAGE_KEY_ENCRYPTION_OR_WRAPPING_K0,
                                    HEADER_MODE_OF_USE_ENCRYPT_DECRYPT_WRAP_UNWRAP_B,
                                    HEADER_ALGORITHM_TRIPLE_DES_TDES_T,
                                    local_certificate,
                                    local_cert_private_key,
                                    ca_key_arn,
                                    apc_client)
    print("Imported KEK: ", kek_key_arn)
    check_tdes_kcv(KEK, kek_key_arn)

    print("Importing a PEK with TR 31")
    pek_key_arn = tr31.import_tr31(KEK,
                                   PEK,
                                   HEADER_EXPORTABILITY_EXPORTABLE_UNDER_TRUSTED_KEY_E,
                                   HEADER_KEY_USAGE_PIN_ENCRYPTION_P0,
                                   HEADER_MODE_OF_USE_ENCRYPT_DECRYPT_WRAP_UNWRAP_B,
                                   HEADER_ALGORITHM_TRIPLE_DES_TDES_T,
                                   kek_key_arn,
                                   apc_client)
    print("Imported PEK: ", pek_key_arn)
    check_tdes_kcv(PEK, pek_key_arn)

    print("Exporting a PEK with TR 31")
    exported_pek_hex_tr31 = tr31.export_tr31(kek_key_arn, KEK, pek_key_arn, apc_client)
    if exported_pek_hex_tr31 != PEK:
        print("Exported PEK does not match original PEK")
    else:
        print("Exported PEK matches original PEK")

    print("Exporting a PEK with TR 34")
    exported_pek_hex_tr34 = tr34.export_tr_34(pek_key_arn, ca_key_arn,
                                              local_certificate, local_cert_private_key, apc_client)
    if exported_pek_hex_tr34 != PEK:
        print("Exported PEK does not match original PEK")
    else:
        print("Exported PEK matches original PEK")

    print("Importing BDK TDES with TR31")
    bdk_tdes_key_arn = tr31.import_tr31(KEK,
                                        BDK,
                                        HEADER_EXPORTABILITY_EXPORTABLE_UNDER_TRUSTED_KEY_E,
                                        HEADER_KEY_USAGE_BDK_BASE_DERIVATION_KEY_B0,
                                        HEADER_MODE_OF_USE_KEY_USED_TO_DERIVE_OTHER_KEYS_X,
                                        HEADER_ALGORITHM_TRIPLE_DES_TDES_T,
                                        kek_key_arn,
                                        apc_client)
    print("Imported TDES BDK: ", bdk_tdes_key_arn)
    check_tdes_kcv(BDK, bdk_tdes_key_arn)

    print("Importing BDK AES with TR31")
    bdk_aes_key_arn = tr31.import_tr31(KEK,
                                       BDK,
                                       HEADER_EXPORTABILITY_EXPORTABLE_UNDER_TRUSTED_KEY_E,
                                       HEADER_KEY_USAGE_BDK_BASE_DERIVATION_KEY_B0,
                                       HEADER_MODE_OF_USE_KEY_USED_TO_DERIVE_OTHER_KEYS_X,
                                       HEADER_ALGORITHM_AES_A,
                                       kek_key_arn,
                                       apc_client)
    print("Imported AES BDK: ", bdk_aes_key_arn)
    # AES KCV is calculated differently

    print("Importing MAC with TR31")
    mac_key_arn = tr31.import_tr31(KEK,
                                   MAC,
                                   HEADER_EXPORTABILITY_EXPORTABLE_UNDER_TRUSTED_KEY_E,
                                   HEADER_KEY_USAGE_ISO_9797_1_MAC_ALGORITHM_3_M3,
                                   HEADER_MODE_OF_USE_GENERATE_VERIFY_C,
                                   HEADER_ALGORITHM_TRIPLE_DES_TDES_T,
                                   kek_key_arn,
                                   apc_client)
    print("Imported MAC: ", mac_key_arn)
    check_tdes_kcv(MAC, mac_key_arn)

    print("Deleting keys")
    delete_key(kek_key_arn)
    delete_key(pek_key_arn)
    delete_key(bdk_tdes_key_arn)
    delete_key(bdk_aes_key_arn)
    delete_key(mac_key_arn)
    delete_key(ca_key_arn)
    print("Done!")
