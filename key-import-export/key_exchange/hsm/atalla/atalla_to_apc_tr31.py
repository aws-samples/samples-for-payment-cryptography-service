import json
import helpers.atalla_helper as atalla_helper
import helpers.csr_helper as csr_helper
from typing import Tuple

from Crypto.Hash import SHA256
from Crypto.PublicKey.RSA import construct
from oscrypto import asymmetric
import helpers.aws_private_ca_helper as private_ca_helper
import helpers.apc_helper as apc_helper


from cryptography import x509
from cryptography.hazmat.primitives import serialization
import argparse
import base64

""" 
Usage - python3 atalla_to_apc_tr31.py --host localhost --port 7000 
            -wrappingKey "1kDNE000,14FB26DD179D6AD587FA0181E599F6CC07F0C8D2AAA2334D,BB6AE577B37A1CD7" 
            --wrappedKey "1CDNE000,55343DEFA0898223CCCDD33AAAFFFF2342B09234ABCDEF54,CDA43234FFFED091" 
            --apcWrappingKeyARN "arn:aws:payment-cryptography:us-west-2:111222333444:key/rd56grgskugzelkz
"""
def export_tr31(working_key,wrapping_key,atalla_address):

    print("Exporting working key using command 11A using TR-31 key block version B. This assumes the working key is not a MAC key. If MAC key, use either of values M0,M1,M3. Refer to Atalla doc for command 11A")
    print("The exportability of the key is is copied from byte 4 of AKB header of the working key")
    data = '<11A#B###' + wrapping_key + '#' + working_key + '#' + '00#0##>'
    response = atalla_helper.send_data(atalla_address, data.encode(), '<21A#(.*?)#(.*?)#>', b'>') #<220#Public Key#Private Key#Check Digits#[Key slot#]>
    tr31WorkingKey = response[0]
    tr31WorkingKeyKCV = response[1]
    return tr31WorkingKey,tr31WorkingKeyKCV


if __name__ == "__main__":

    print('###############################################################################')
    print ("Sample code to export a working key from Atalla HSM and import into AWS Payment Cryptography using TR-31")
    print ("This is currently intended for 3DES keys.")
    print ("This code is sample only and comes with no warranty")
    print('###############################################################################')

    parser = argparse.ArgumentParser(prog='TR-31 Atalla/Uimaco Export following AWS Payment Cryptography Key Import Concepts',
                                     description='Sample code to generate a TR-31 format working key from Utimaco AT1000 and import into AWS Payment Cryptography',
                                     epilog='This is intended as sample code and comes with no waranty and is not intended for us with production keys.')
    parser.add_argument("--wrappingKey", help="Wrapping key that wraps the working key in Atalla", default="")
    parser.add_argument("--wrappedKey", help="Wrapped Key to export from Atalla", default="")
    parser.add_argument("--apcWrappingKeyARN", help="Wrapping key (KEK) in APC - which has exported from Atalla to APC. This should be the same key from the wrappingKey arg", default="")
    parser.add_argument("--host", help="Atalla Host", default="localhost")
    parser.add_argument("--port", help="Atalla Port", default=7000,type=int)
    
    args = parser.parse_args()

    tr31WorkingKey, tr31WorkingKeyKCV = export_tr31(args.wrappedKey, args.wrappingKey, (args.host, args.port))
    print("TR-31 Working Key: ", tr31WorkingKey)
    print("TR-31 Working Key KCV: ", tr31WorkingKeyKCV)
    importedKeyARN,importedKeyKCV= apc_helper.importTR31Payload(tr31WorkingKey,args.apcWrappingKeyARN)
    print("Imported Key ARN: ", importedKeyARN)
    print("Imported Key KCV: ", importedKeyKCV)
    