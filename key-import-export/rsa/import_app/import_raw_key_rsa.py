'''
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software
without restriction, including without limitation the rights to use, copy, modify,
merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The following api calls may be subject to https://aws.amazon.com/service-terms/ section 2 - Beta & Previews

Usage - python import_raw_key_rsa.py --action importclearkey --clearkey 6E46FE409DF704BCA75E7FF270B65E73 --algorithm A
'''
import boto3
import botocore.session
import secrets
import argparse
import sys
import termios
import tty
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import base64
import binascii
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Cipher import DES3

service = 'payment-cryptography'
regionName = 'us-east-1'

session = botocore.session.Session()
config = session.get_scoped_config()

def _get_region():
    return config.get('region', regionName)

def DeleteKey(keyArn):
    apc_client = boto3.client('payment-cryptography', region_name=_get_region())
    apc_client.delete_key(KeyIdentifier=keyArn, DeleteKeyInDays=3)

def GetParametersForImport():
    apc_client = boto3.client('payment-cryptography', region_name=_get_region())
    import_parameters_res = apc_client.get_parameters_for_import(
        KeyMaterialType='KEY_CRYPTOGRAM',
        WrappingKeyAlgorithm='RSA_4096')
    
    responseDict = dict()
    responseDict["ImportToken"] = import_parameters_res['ImportToken']
    responseDict["WrappingKeyAlgorithm"] = import_parameters_res["WrappingKeyAlgorithm"]
    responseDict["WrappingKeyCertificateChain"] = import_parameters_res["WrappingKeyCertificateChain"]
    responseDict["WrappingKeyCertificate"] = import_parameters_res['WrappingKeyCertificate']
    return responseDict

def ImportRootCert(PublicKeyCertificate):
    apc_client = boto3.client('payment-cryptography', region_name=_get_region())
    imported_symmetric_key_res = apc_client.import_key(
                Enabled=True,
                KeyCheckValueAlgorithm="CMAC", 
                KeyMaterial={
                    "RootCertificatePublicKey": {
                        "KeyAttributes": {
                            "KeyAlgorithm": "RSA_4096", 
                            "KeyClass": "PUBLIC_KEY", 
                            "KeyModesOfUse": {
                                "Decrypt": false, 
                                "DeriveKey": false, 
                                "Encrypt": false, 
                                "Generate": false, 
                                "NoRestrictions": false, 
                                "Sign": false, 
                                "Unwrap": false, 
                                "Verify": true, 
                                "Wrap": false
                            }, 
                            "KeyUsage": "TR31_S0_ASYMMETRIC_KEY_FOR_DIGITAL_SIGNATURE"
                        }, 
                        "PublicKeyCertificate": PublicKeyCertificate
                    } 
                } 
            )
    return imported_symmetric_key_res["Key"]["KeyArn"]

def ImportKey(WrappedKey,ImportToken,KeyAlgorithm="AES_128",KeyModesOfUse='{"Decrypt": true, "DeriveKey": false, "Encrypt": true, "Generate": false,"NoRestrictions": false, "Sign": false, "Unwrap": true, "Verify": false, "Wrap": true}',KeyUsage="TR31_K0_KEY_ENCRYPTION_KEY",KCVType="CMAC"):
    apc_client = boto3.client('payment-cryptography', region_name=_get_region())
    imported_symmetric_key_res = apc_client.import_key(
            Enabled=True,
            KeyMaterial={
                "KeyCryptogram": {
                "Exportable": True, 
                "ImportToken": ImportToken, 
                "KeyAttributes": {
                    "KeyAlgorithm": KeyAlgorithm, 
                    "KeyClass": "SYMMETRIC_KEY", 
                    "KeyModesOfUse": KeyModesOfUse, 
                    "KeyUsage": KeyUsage
                }, 
                "WrappedKeyCryptogram": WrappedKey, 
                "WrappingSpec": "RSA_OAEP_SHA_256"
            } 
            },
            KeyCheckValueAlgorithm=KCVType, Tags=[]
        )
    
    
    
    print('************************ DONE *****************')
    print('Key Arn: ' + imported_symmetric_key_res['Key']['KeyArn'])
    print('Reported KCV: ' + imported_symmetric_key_res['Key']['KeyCheckValue'])
    """ print('Calculated KCV: ' + DES3.new(symmetric_key_binary, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()) """
    print('Reported Type: ' + imported_symmetric_key_res['Key']['KeyAttributes']['KeyAlgorithm'])
    
    return imported_symmetric_key_res["Key"]["KeyArn"],imported_symmetric_key_res["Key"]["KeyCheckValue"]

def GenerateAes128SymmetricKey():
    ephemeral_key = secrets.token_bytes(16)
    return ephemeral_key

def GenerateAesKcv(key):
    cobj = CMAC.new(key, ciphermod=AES)
    cobj.update(binascii.unhexlify('00000000000000000000000000000000'))
    kcv = cobj.hexdigest()[0:6].upper()
    return kcv

def GenerateTdes_2Key_SymmetricKey():
    ephemeral_key = secrets.token_bytes(16)
    return ephemeral_key

def GenerateTdesKcv(key):
    kcv = DES3.new(key, DES3.MODE_ECB).encrypt(bytes.fromhex('0000000000000000'))[:3].hex().upper()
    return kcv

def WrapKey(wrappingCert,keyToWrap):
    wrappingCert = x509.load_pem_x509_certificate(base64.b64decode(wrappingCert))
    publicKey = wrappingCert.public_key()

    encrypted = publicKey.encrypt(
        keyToWrap,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return binascii.hexlify(encrypted).decode("UTF-8").upper()


def _calculate_kcv(key_bytes: bytes, algo: str) -> str:
    """Calculate KCV. algo is 'A' for AES or 'T' for TDES."""
    if algo == 'A':
        return CMAC.new(key_bytes, msg=bytes(AES.block_size), ciphermod=AES).digest()[:3].hex().upper()
    else:
        return DES3.new(key_bytes, DES3.MODE_ECB).encrypt(bytes(DES3.block_size))[:3].hex().upper()


def _read_masked_hex(prompt: str, optional: bool = False) -> str:
    """Read hex from the terminal echoing '*' per character. Returns stripped hex or '' if optional+empty."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    chars = []
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        tty.setraw(fd)
        while True:
            ch = sys.stdin.read(1)
            if ch in ('\r', '\n'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                break
            elif ch in ('\x7f', '\x08'):
                if chars:
                    chars.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == '\x03':
                sys.stdout.write('\n')
                raise KeyboardInterrupt
            else:
                chars.append(ch)
                sys.stdout.write('*')
                sys.stdout.flush()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ''.join(chars).replace(' ', '')


def prompt_key_components(algo: str) -> bytes:
    """Interactive masked component entry. Returns combined key as bytes."""
    VALID_LENGTHS = {
        'A': {16: 'AES-128', 24: 'AES-192', 32: 'AES-256'},
        'T': {16: 'TDES-2KEY', 24: 'TDES-3KEY'},
    }

    def read_component(label: str, expected_len: int = 0, optional: bool = False) -> str:
        while True:
            raw = _read_masked_hex(f"  Enter {label} (hex): ", optional=optional)
            if optional and raw == '':
                return ''
            if not raw:
                print("  Error: value cannot be empty.")
                continue
            if not all(c in '0123456789abcdefABCDEF' for c in raw):
                print("  Error: only hex characters (0-9, a-f, A-F) are allowed.")
                continue
            if len(raw) % 2 != 0:
                print(f"  Error: must be an even number of hex characters (got {len(raw)}).")
                continue
            key_bytes_len = len(raw) // 2
            valid = VALID_LENGTHS[algo]
            if key_bytes_len not in valid:
                valid_desc = ', '.join(f"{b*2} hex chars ({v})" for b, v in valid.items())
                print(f"  Error: {key_bytes_len} bytes is not a valid {'AES' if algo=='A' else 'TDES'} key length.")
                print(f"  Valid lengths: {valid_desc}.")
                continue
            if expected_len and key_bytes_len != expected_len:
                print(f"  Error: this component is {key_bytes_len} bytes but previous components were {expected_len} bytes.")
                continue
            kcv = _calculate_kcv(bytes.fromhex(raw), algo)
            print(f"  {label} KCV: {kcv}")
            return raw

    print("\n--- Key Component Entry ---")
    c1 = read_component("Component 1")
    expected = len(c1) // 2
    c2 = read_component("Component 2", expected_len=expected)
    c3 = read_component("Component 3 (press Enter to skip for 2-component entry)", expected_len=expected, optional=True)

    if c3 == '':
        combined = bytes(a ^ b for a, b in zip(bytes.fromhex(c1), bytes.fromhex(c2)))
    else:
        combined = bytes(a ^ b ^ c for a, b, c in zip(bytes.fromhex(c1), bytes.fromhex(c2), bytes.fromhex(c3)))

    combined_kcv = _calculate_kcv(combined, algo)
    print(f"\n  Combined key KCV: {combined_kcv}")
    print("---------------------------\n")

    while True:
        confirm = input(f"  Confirm import of key with KCV [{combined_kcv}]? (yes/no): ").strip().lower()
        if confirm == 'yes':
            break
        elif confirm == 'no':
            print("  Import cancelled.")
            sys.exit(0)
        else:
            print("  Please type 'yes' or 'no'.")

    return combined

########################################################################

# Mapping from TR-31 key type codes to AWS Payment Cryptography KeyUsage values
TR31_KEY_USAGE_MAP = {
    'K0': 'TR31_K0_KEY_ENCRYPTION_KEY',
    'K1': 'TR31_K1_KEY_BLOCK_PROTECTION_KEY',
    'B0': 'TR31_B0_BASE_DERIVATION_KEY',
    'D0': 'TR31_D0_SYMMETRIC_DATA_ENCRYPTION_KEY',
    'P0': 'TR31_P0_PIN_ENCRYPTION_KEY',
    'E0': 'TR31_E0_EMV_MKEY_APP_CRYPTOGRAMS',
    'E1': 'TR31_E1_EMV_MKEY_CONFIDENTIALITY',
    'E2': 'TR31_E2_EMV_MKEY_INTEGRITY',
    'E3': 'TR31_E3_EMV_MKEY_OTHER',
    'E6': 'TR31_E6_EMV_MKEY_OTHER',
    'C0': 'TR31_C0_CARD_VERIFICATION_KEY',
}

# Mapping from TR-31 mode of use codes to AWS Payment Cryptography KeyModesOfUse values
def get_key_modes_of_use(mode_of_use):
    modes = {
        'B': {'Encrypt': True, 'Decrypt': True, 'Wrap': True, 'Unwrap': True},
        'X': {'DeriveKey': True},
        'N': {'NoRestrictions': True},
        'E': {'Encrypt': True, 'Wrap': True},
        'D': {'Decrypt': True, 'Unwrap': True},
        'C': {'Encrypt': True, 'Decrypt': True},
        'G': {'Generate': True},
        'V': {'Verify': True},
    }
    return modes.get(mode_of_use, {'NoRestrictions': True})

########################################################################

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("--action", help="Actions this script can perform",choices={"generateWrappingKey","importKey","demo","importclearkey"},default="demo")
    parser.add_argument("--importToken", "-i", help="Pointer to key to unwrap key with",default="")
    parser.add_argument("--wrappedKey", "-w", help="Wrapped Key to import in RSA cryptogram format")
    parser.add_argument("--clearkey", "-k", help="Clearkey to import. If using key components, leave this empty.",default="")
    parser.add_argument("--component1", help="First key component (hex). All three components are XORed to form the final key.", default="")
    parser.add_argument("--component2", help="Second key component (hex).", default="")
    parser.add_argument("--component3", help="Third key component (hex).", default="")
    parser.add_argument("--prompt-components", action="store_true",
                        help="Interactively prompt for key components with masked input and KCV display.")
    parser.add_argument("--algorithm", "-a", help="Key algorithm - (T)des or (A)es (default: T)", default="T", choices={"T","A"})
    parser.add_argument("--region", "-r", help="AWS region (optional, overrides profile/environment default)", default=None)
    parser.add_argument("--keytype", "-t", help="Key Type according to TR-31 norms. For instance K0, B0, etc", default="K0",
                        choices=['K0', 'K1', 'B0', 'D0', 'P0', 'E0', 'E3', 'E6', 'E1', 'C0', 'E2'])
    parser.add_argument("--modeofuse", "-m", help="Mode of use according to TR-31 norms. For instance B (encrypt/decrypt), X (derive key)", default="B",
                        choices=['B', 'X', 'N', 'E', 'D', 'C', 'G', 'V'])

    args = parser.parse_args()

    if args.region:
        regionName = args.region

    # --prompt-components implies importclearkey
    if args.prompt_components and args.action == 'demo':
        args.action = 'importclearkey'

    if args.action == 'generateWrappingKey':
         print("Generating a wrapping key.  Export your key using this wrapping key and then call with action=importKey")
         print(GetParametersForImport())
    elif args.action == 'demo':
        if args.wrappedKey == "" or args.importToken == "":
            print("Demo mode.  Generates a wrapping key on the service, then generates a random symmetric key. This symmetric key is then encrypted using the wrapping key. \
                  Finally, the key is loaded into the service. The key is imported as a KEK but that can be modified.")
            print("Get parameters for import")
            importRes = GetParametersForImport()
            importToken = importRes["ImportToken"]
            wrappingKeyAlgorithm = importRes["WrappingKeyAlgorithm"]
            wrappingKeyCertificateChain = importRes["WrappingKeyCertificateChain"]
            wrappingKeyCertificate = importRes["WrappingKeyCertificate"]

            KeyAlgo = 'TDES_2KEY' #AES_128 or TDES_2KEY

            if KeyAlgo == 'AES_128':
                print("Generating AES-128 symmetric key")
                sampleKey = GenerateAes128SymmetricKey()
                sourceKcv = GenerateAesKcv(sampleKey)
                KcvType= "CMAC"
            elif KeyAlgo == 'TDES_2KEY':
                print("Generating 2 key TDES symmetric key")
                KcvType= "ANSI_X9_24"
                sampleKey = GenerateTdes_2Key_SymmetricKey()
                sourceKcv = GenerateTdesKcv(sampleKey)
            else:
                print("Invalid Key Algorithm for this sample code")
                sys.exit(1)

            print("Generated Key. Algo:",KeyAlgo,". Clear Key:",binascii.hexlify(sampleKey).decode()," Calculated KCV: ", sourceKcv)
            wrappedKey = WrapKey(wrappingKeyCertificate,sampleKey)
            print("Wrapped keyType",KeyAlgo,"Result:",wrappedKey)

            ImportKeyArn,importedKcv = ImportKey(wrappedKey,importToken,KeyAlgorithm=KeyAlgo,KCVType=KcvType,
                                                  KeyModesOfUse=get_key_modes_of_use(args.modeofuse),
                                                  KeyUsage=TR31_KEY_USAGE_MAP.get(args.keytype, 'TR31_K0_KEY_ENCRYPTION_KEY'))
            print("Done - Imported Key Cryptogram:",ImportKeyArn,"KCV:",importedKcv) 
            print("KCV Matches?",importedKcv==sourceKcv)
    elif args.action == "importclearkey":
        # Determine the clear key: prompt, --clearkey, or --component flags
        has_components = args.component1 or args.component2 or args.component3
        algo = args.algorithm
        suppress_key_output = args.prompt_components

        if args.prompt_components:
            if args.clearkey or has_components:
                raise Exception('Cannot combine --prompt-components with --clearkey or --component flags.')
            algo_name = "AES" if algo == "A" else "TDES"
            print("\n--- Key Import Summary ---")
            print(f"  Algorithm  : {algo_name}")
            print(f"  Key Type   : {args.keytype}")
            print(f"  Mode of Use: {args.modeofuse}")
            print("--------------------------")
            clearkey = prompt_key_components(algo)
        elif args.clearkey and has_components:
            raise Exception('Provide either --clearkey or all three --component flags, not both.')
        elif has_components:
            if not (args.component1 and args.component2 and args.component3):
                raise Exception('All three key components (--component1, --component2, --component3) must be provided.')
            c1 = bytes.fromhex(args.component1.replace(" ", ""))
            c2 = bytes.fromhex(args.component2.replace(" ", ""))
            c3 = bytes.fromhex(args.component3.replace(" ", ""))
            if not (len(c1) == len(c2) == len(c3)):
                raise Exception('All three key components must be the same length. Got %d, %d, %d bytes.' % (len(c1), len(c2), len(c3)))
            clearkey_hex = bytes(a ^ b ^ c for a, b, c in zip(c1, c2, c3)).hex()
            print("Component 1:", args.component1)
            print("Component 2:", args.component2)
            print("Component 3:", args.component3)
            print("Combined key (XOR):", clearkey_hex.upper())
            clearkey = binascii.unhexlify(clearkey_hex)
        elif args.clearkey:
            clearkey = binascii.unhexlify(args.clearkey.replace(" ", ""))
        else:
            print("Missing key to import. Provide --clearkey, --component flags, or --prompt-components.")
            sys.exit(1)

        if clearkey != b"":
            print("Import a clear key")
            print("Get parameters for import")
            importRes = GetParametersForImport()
            importToken = importRes["ImportToken"]
            wrappingKeyCertificate = importRes["WrappingKeyCertificate"]

            Keylength = len(clearkey)
            if algo == "A":
                if Keylength == 16:
                    KeyAlgo = 'AES_128'
                else:
                    print("Invalid Key length for AES under RSA")
                    sys.exit(1)
            elif algo == "T":
                if Keylength == 16:
                    KeyAlgo = 'TDES_2KEY'
                elif Keylength == 24:
                    KeyAlgo = 'TDES_3KEY'
                else:
                    print("Invalid Key length for TDES")
                    sys.exit(1)

            if algo == 'A':
                print("Importing AES symmetric key")
                sourceKcv = GenerateAesKcv(clearkey)
                KcvType = "CMAC"
            elif algo == 'T':
                print("Importing TDES symmetric key")
                KcvType = "ANSI_X9_24"
                sourceKcv = GenerateTdesKcv(clearkey)
            else:
                print("Invalid Key Algorithm for this sample code")
                sys.exit(1)
        else:
            print("Missing key to import")
            sys.exit(1)

        if not suppress_key_output:
            print("Key Info Algo:", KeyAlgo, ". Clear Key:", binascii.hexlify(clearkey).decode(), " Calculated KCV: ", sourceKcv)
        else:
            print("Key Info Algo:", KeyAlgo, " Calculated KCV: ", sourceKcv)

        wrappedKey = WrapKey(wrappingKeyCertificate, clearkey)

        ImportKeyArn, importedKcv = ImportKey(wrappedKey, importToken, KeyAlgorithm=KeyAlgo, KCVType=KcvType,
                                              KeyModesOfUse=get_key_modes_of_use(args.modeofuse),
                                              KeyUsage=TR31_KEY_USAGE_MAP.get(args.keytype, 'TR31_K0_KEY_ENCRYPTION_KEY'))
        print("Done - Imported Key Cryptogram:", ImportKeyArn, "KCV:", importedKcv)
        print("KCV Matches?", importedKcv == sourceKcv)
    else:
        if args.wrappedKey == "" or args.importToken == "":
            print("Import Token and wrappedKey required for importKey")
            sys.exit(1)
        ImportKeyArn = ImportKey(args.wrappedKey,args.importToken)
        print("Step #1 - Imported Key Cryptogram:",ImportKeyArn) 