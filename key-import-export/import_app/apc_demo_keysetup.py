# python3 -m pip install psec
# python3 -m pip install binascii
# python3 -m pip install boto3
# python3 -m pip install pycryptodome


"""
This script is intended to import/generate all the keys needed for the AWS Payment Cryptography demo
"""
import import_tr34_raw_key_to_apc as tr34
import import_tr31_raw_key_to_apc as tr31
import boto3

""" Key encryption key which will be used to import subsequent keys """
KEK = '79ADAEF3212AADCE312ACE422ACCFEFB'
""" KEK = '8A8349794C9EE9A4C2927098F249FED6' """

""" Base Derivation Key which will be used to generate DUKPT """
BDK = '8A8349794C9EE9A4C2927098F249FED6'
bdkAlias = 'alias/MerchantTerminal_BDK'

""" Pin Encryption Key. For the samples, the same key will be shared between ATM, Pin tranlation service and Issuer. 
This is to show that ATM can directly talk to issuer service to set and verify pin. 
ATM can also go through intermediate PinTranslateService which makes call to Issuer to set and verify Pin. """
PEK = '545E2AADFD5EC42F2F5BE5E3ADC75E9B290252A1A219B380'
pinTranslateServicePekAlias = "alias/pinTranslateServicePek"
issuerPekAlias = 'alias/issuerPek'

issuerGenerationAlias = 'alias/issuerPinValidationKey'

""" MAC key for HMAC verification """
MAC = '75BDAEF54587CAE6563A5CE57B4B9F9F'
""" MAC = '8A8349794C9EE9A4C2927098F249FED6' """
macAlias = 'alias/tr31_macValidationKey'


apc_client = boto3.client('payment-cryptography')

def GeneratePvk(issuerGenerationAlias):
    #create PVK
    keyModesOfUse = {'Generate':True,'Verify':True}
    keyAttributes = {'KeyAlgorithm':'TDES_2KEY','KeyUsage':'TR31_V2_VISA_PIN_VERIFICATION_KEY','KeyClass':'SYMMETRIC_KEY','KeyModesOfUse':keyModesOfUse}

    PvkKeyARN = apc_client.create_key(Exportable=True,KeyAttributes=keyAttributes)['Key']['KeyArn']

    try:
        aliasList = apc_client.get_alias(AliasName=issuerGenerationAlias)

        if 'KeyArn' in aliasList['Alias']:
            keyDetails = apc_client.get_key(KeyIdentifier=aliasList['Alias']['KeyArn'])
            if (keyDetails['Key']['KeyState'] == 'CREATE_COMPLETE'):
                apc_client.delete_key(KeyIdentifier=aliasList['Alias']['KeyArn'], DeleteKeyInDays=3)
        apc_client.update_alias(AliasName=aliasList['Alias']['AliasName'],KeyArn=PvkKeyARN)

    except apc_client.exceptions.ResourceNotFoundException:
        aliasList = apc_client.create_alias(AliasName=issuerGenerationAlias,KeyArn=PvkKeyARN)
    return PvkKeyARN,issuerGenerationAlias

if __name__ == "__main__":

    print("")
    print("*********Importing a KEK for importing subsequent keys*********")
    print("")

    tr34_response = tr34.importTr34("ONLINE",KEK,"E","K0","B","","")
    print("KEK/KPBK/ZMK ARN:",tr34_response[0])


    print("")
    print("*********Importing a BDK for DUKPT*********")
    print("")
    response = tr31.importTR31(KEK,BDK,"E","B0","X","T","ONLINE",tr34_response[0],None,bdkAlias)
    print("BDK ARN:",response[0])
    print("Alias",response[1])


    print("")
    print("*********Importing a PEK for communicating with ATM*********")
    print("")
    response = tr31.importTR31(KEK,PEK,"E","P0","B","T","ONLINE",tr34_response[0],None,pinTranslateServicePekAlias)
    print("PEK(ATM PEK) ARN:",response[0])
    print("Alias:",response[1])

    print("")
    print("*********Importing a PEK for Pin Translate Service to Issuer communication. This service sits between between issuer and ATM) *********")
    print("")
    response = tr31.importTR31(KEK,PEK,"E","P0","B","T","ONLINE",tr34_response[0],None,issuerPekAlias)
    print("PEK(ATM PEK) ARN:",response[0])
    print("Alias:",response[1])

    print("")
    print("*********Generating a PGK for generating a PVV*********")
    print("")

    response = GeneratePvk(issuerGenerationAlias)

    print("Pin Verification Value ARN",response[0])
    print("Pin Verification Value Alias",response[1])

    print("")
    print("*********Generating a MAC key for MAC verification********")
    print("")

    response =  tr34.importTr34("ONLINE",MAC,"E","M3","C","")

    try:
        alias_res = apc_client.get_alias(AliasName=macAlias)
    except apc_client.exceptions.ResourceNotFoundException:
        alias_res = apc_client.create_alias(AliasName=macAlias)

    
    macResponse = apc_client.update_alias(AliasName=macAlias,KeyArn=response[0])
    print("MAC Key Alias:",macResponse['Alias']['AliasName'])
    print("MAC Key ARN:",macResponse['Alias']['KeyArn'])

    
    print("")
    print("*********Done*********")
    print("")

