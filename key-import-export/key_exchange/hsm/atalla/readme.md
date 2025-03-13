# TR-34 Exchange between Atalla -> AWS Payment Cryptography (APC)
This script will exchange the Key Exchange Key (KEK) from Atalla into APC, thus bootstrapping it for migration of working keys from Atalla to APC.

## Assumptions
1. This script assumes that you have access to an Atalla HSM and can perform administrative commands such as 12A
2. The Atalla HSM is configured using a TDES MFK.  Slight changes might be needed if you are using an AES MFK
3. Working keys to be migrated are 2-key or 3-key TDES
4. The HSM is enabled for the following commands: 12A,120,136,139 for initial exchange and then 11A and option E2 to migrate working keys using TR-31.
5. You have access to AWS Private CA or access to another CA of your chosing to sign a CSR.


## Prerequisites

 1. Call [GetParametersForImport](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_GetParametersForImport.html). Save the output under [keys/params_for_import.json](./keys/params_for_import.json)
 2. Import the KRD (in this case is APC) Leaf certificate [WrappingKeyCertificate] from [params_for_import.json](./keys/params_for_import.json).json into Atalla.
 **_NOTE:_** Typically you would import the CA certificate and then root certificate.  However, the command for importing chained certificates (123) does not support the SHA-512 hash used by the APC service, so you must directly trust the leaf cert using 12A instead which is a manual process requiring dual control.

      Steps - 
      1. Get the modulus of the public key cert. Example - ```echo "LS0tLS1CRUdJTiBDRVJUSUZJQ..." | base64 -d | openssl x509 -modulus -noout```
      2. Trust KRD public key on Atalla.
      In order to establish trust, use command 12A. This is a 2 step command that requires dual control with the final output being an AKB of the public key.
         - Step 1 - ```<12A#1kREE000#010001#modulus##>``` which returns a security challenge. The 12A command needs to be rerun after the security challenge is completed via admin screen on Atalla. 
         - Step 2 -  
            ```<12A#1kREE000#010001#modulus#security channelge answer#>```. The output of the second command gives the public key akb and will look something like ```<22A#OK#1kREE000,00030100010100B0357EB48EEEEAE......#>```
         - Save output from the header onwards to the end of the response (```1kREE000,00030.....BBB,26A8A315```) on to the [krd_public_key_akb file](./keys/tr34_offline_krd_public_key_akb).

 ## Script Usage
 ```
 1. python -m venv .venv
 2. source .venv/bin/activate 
 3. pip3 install -r requirements.txt
 4. python3 atalla_to_apc_tr34.py <hsm address> <hsm port> 
    Example: python3 atalla_to_apc_tr34.py '127.0.0.1' 7000 
 ```

## The atalla_to_apc_tr34.py script does the following - 
1. Generate Signing Key on Atalla (command 120)
2. Generate CSR within this sample code and then sign on the Atalla (command 139). Update the CSR subject information in file `atalla_to_apc_tr34.py` if desired.
 **_NOTE:_** although command 124 is typically used for digital signatures, it cannot be used when the purpose of the key will be to sign TR-34 payloads.
3. Have CSR signed by CA of your choice ([AWS Private Certificate Authority](https://aws.amazon.com/private-ca/) is used here)
4. Trust Signing CA on APC - Use APC.[Import Public Root KeyCertificate](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ImportKey.html)
5. Build TR-34 payload and generate KEK (136).  Save Atalla KEK for future use.
6. Sign TR-34 payload (139)
7. Build combined payload using the TR-34 non-CMS payload structure  (code sample - not cryptographic)
8. Import key into APC by calling [ImportKey](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ImportKey.html)

## TR-34 KEK Exchange Flow
![Atalla TR-34 Flow](./assets/atalla-apc-tr34-key-exchange-sequence-diagram%20-%20Key%20Exchange.png)

### After running the script and having KEK exchanged, you can import the working key 2 ways below - 

#### 1. atalla_to_apc_tr31.py script
Pass the AKB of wrapping key from step 5 above, AKB of working key and ARN of the wrapping key (KEK) imported into APC from step 8 above
   - ```
      python3 atalla_to_apc_tr31.py --host localhost --port 7000 
            -wrappingKey "1kDNE000,14FB26DD179D6AD587FA0181E599F6CC07F0C8D2AAA2334D,BB6AE577B37A1CD7" 
            --wrappedKey "1CDNE000,55343DEFA0898223CCCDD33AAAFFFF2342B09234ABCDEF54,CDA43234FFFED091" 
            --apcWrappingKeyARN "arn:aws:payment-cryptography:us-west-2:111222333444:key/rd56grgskugzelkz
      ```

#### 2. Using CLI

Use TR-31 to export keys using KEK generated in step #5 (command 11A)
   - Example 
      - Request ```<11A#B###1kDNE000,14FB26DD179D6AD587FA0181E599F6CC07F0C8D2AAA2334D,BB6AE577B37A1CD7#1CDNE000,55343DEFA0898223CCCDD33AAAFFFF2342B09234ABCDEF54,CDA43234FFFED091#00#0##>```
      where, field 4 is the KEK generated from step 5 above and field 5 is the AKB of the working key to export.

      - Response ```<21A#BBAA4453FDDCC089AB8C50BB184BBA7499EA610346321F5952C602204AE6C4FFF89F547A2E51E9456456DDDAACCCC556#1786#>```
      where field 1 is the TR-31 block and field 2 is the check digits that should match with the key check value from APC after import. 

 **_NOTE:_** Unless otherwise enabled, option E2 on Atalla may restrict your ability to output certain keys (including other KEK)s. This is a common source of error 0607 (security violation)

 ## AWS Resource Used
 1. This sample uses a Private CA short lived CA.  To limit charges, delete the CA after completing testing
 2. This sample creates key(s) on AWS Payment Cryptography.  To limit charges, delete  key(s) after completing testing