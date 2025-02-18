# python3 -m pip install psec
# python3 -m pip install binascii
# python3 -m pip install boto3
# python3 -m pip install pycryptodome

import psec
import binascii
import boto3
import argparse


def constructTr31Header(algo,exportMode,keyType,modeOfUse):

    versionID = 'D' if algo == 'A' else 'B'
    length = '9999' #this library will overwrite it with the correct value

    header = versionID + length + keyType + algo + modeOfUse + "00" + exportMode + "0000"

    header = psec.tr31.Header(
        version_id=versionID,     # Version B as recommended for TDES
        key_usage=keyType,     # PIN Encryption
        algorithm=algo,      # TDES
        mode_of_use=modeOfUse,    # Encryption only
        version_num="00",   # No version
        exportability=exportMode
    )

    return header


def importTR31(kbpk_clearkey,wk_clearkey,exportmode,keytype,modeofuse,algorithm,runmode,kbpkkey_apcIdentifier,region,aliasName=None):

    kbpkkey = binascii.unhexlify(kbpk_clearkey.replace(" ",""))

    binaryWkKey = binascii.unhexlify(wk_clearkey.replace(" ",""))

    wrappedKey = (psec.tr31.wrap(kbpk=kbpkkey, header=constructTr31Header(algorithm,exportmode,keytype,modeofuse), key=binaryWkKey)).upper()

    print("WRAPPED KEY IN TR-31",wrappedKey)

    if runmode == 'OFFLINE':
        print('to complete run import key making sure to update key identifier and wrapped payload')
    else:
        if region==None or region == "":
            apc_client = boto3.client('payment-cryptography')
        else:
            apc_client = boto3.client('payment-cryptography',region_name=region)

        #clean up alias and associated keys
        if aliasName is not None:
            try:
                aliasList = apc_client.get_alias(AliasName=aliasName)
            except apc_client.exceptions.ResourceNotFoundException:
                aliasList = apc_client.create_alias(AliasName=aliasName)

            if 'KeyArn' in aliasList['Alias']:
                apc_client.update_alias(AliasName=aliasList['Alias']['AliasName'])
                keyDetails = apc_client.get_key(KeyIdentifier=aliasList['Alias']['KeyArn'])
                if (keyDetails['Key']['KeyState'] == 'CREATE_COMPLETE'):
                    apc_client.delete_key(KeyIdentifier=aliasList['Alias']['KeyArn'], DeleteKeyInDays=3)

        imported_symmetric_key_res = apc_client.import_key(
            Enabled=True,
            KeyMaterial= {"Tr31KeyBlock": {"WrappingKeyIdentifier": kbpkkey_apcIdentifier,
                                           "WrappedKeyBlock": wrappedKey}}
        )

        print('Imported Key: ' + binaryWkKey.hex())
        print('Key Arn: ' + imported_symmetric_key_res['Key']['KeyArn'])
        print('Reported KCV: ' + imported_symmetric_key_res['Key']['KeyCheckValue'])
        print('Reported Type: ' + imported_symmetric_key_res['Key']['KeyAttributes']['KeyAlgorithm'])

        if aliasName is not None:
            apc_client.update_alias(AliasName=aliasName, KeyArn=imported_symmetric_key_res['Key']['KeyArn'])

        return imported_symmetric_key_res['Key']['KeyArn'],aliasName


if __name__ == "__main__":

    print ("Sample code to encrypt a key in TR-31 format and import it into AWS Payment Cryptography")
    print ("This code assumes the key encryption key (KEK, KBPK, ZCMK) is 3DES but the key to import can be 3DES or AES.")
    print ("Can be run in the default mode where it generates the payload and directly makes all required service calls OR ")
    print ("can be run in offline mode where you can import the payload later on.")


    parser = argparse.ArgumentParser(prog='TR-31 Key Import Sample Code',
                                     description='Sample code to generate a TR-31 format and import it into AWS Payment Cryptography.  This assumes that you have a clear text \
                                     version of the KBPK (Key Block Protection Key) also known as KEK/ZMK/ZMCK, have uploaded it to AWS Payment Cryptography and have its \
                                     associated keyIdentifier (keyARN or keyAlias).  If you have not yet imported it, use import_raw_key_to_apc.py \
                        mode which will directly import the key into the service but can only import 3DES keys. \
                        Alternately, it can be run in offline mode where you specify the inputs and it will provide the payload to be run.',
                                     epilog='This is intended as sample code and comes with no warranty and is not intended for us with production keys.')
    parser.add_argument("--clearkey", help="Clear Text Key to import using TR-31", default="BA6DCE7F5E54F2A7CE45C41A64838C70")
    parser.add_argument("--kbpk_clearkey", help="Clear Text version of KBPK", default="8A8349794C9EE9A4C2927098F249FED6")
    parser.add_argument("--exportmode", "-e", help="Export Mode - E, S or N", default="E",choices=['E', 'S', 'N'])
    parser.add_argument("--algorithm", "-a", help="Algorithm of key - (T)DES or (A)ES", default="T", choices=['A', 'T','R'])
    parser.add_argument("--keytype", "-t", help="Key Type according to TR-31 norms. For instance K0, B0, etc", default="B0",choices=['K0', 'B0', 'D0','P0','D1'])
    parser.add_argument("--modeofuse", "-m", help="Mode of use according to TR-31 norms.  For instance B (encrypt/decrypt),X (derive key)", default="X",choices=['B', 'X', 'N','E','D','G','C','V'])
    parser.add_argument("--runmode", help="Run mode. APC will directly import will offline will only produce tr-31 payload", default="APC",choices=['APC', 'OFFLINE'])
    parser.add_argument("--kbpkkey_apcIdentifier","-z", help="Key identifier for KEK that has already been imported into the service. It should have a keytype of K0.", default="",required=True)

    args = parser.parse_args()

    print ("Key to import:",args.clearkey)
    print ("Key Encryption Key (in cleartext)",args.kbpk_clearkey)
    print ("Key Encryption Key identifier on the service",args.kbpkkey_apcIdentifier)
    print ("Key Encryption Key identifier on the service",args.kbpkkey_apcIdentifier)
    print ("Export Mode:",args.exportmode)
    print ("Key Type:",args.keytype)
    print ("Key Mode of use:",args.modeofuse)
    print ("Key Algorithm:",args.algorithm)

    region = args.kbpkkey_apcIdentifier.split(":")[3]
    print ("Region implied from keyARN",region)


    result = importTR31(kbpk_clearkey=args.kbpk_clearkey,wk_clearkey=args.clearkey,exportmode=args.exportmode, \
                        algorithm=args.algorithm,keytype=args.keytype,modeofuse=args.modeofuse, runmode=args.runmode,kbpkkey_apcIdentifier=args.kbpkkey_apcIdentifier,region=region)




        #print('TR-31 Payload:',wrappedKey)


