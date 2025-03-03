# Import Keys

Importing keys is a prerequisite to run the JAVA samples. 

They Python samples are used to import clear text keys. The key import app already has sample clear text keys defined and can be run as is. The same keys and aliases defined in Python app here are used in the JAVA samples app. Look under `java_sdk_example/src/main/java/aws/sample/paymentcryptography/ServiceConstants.java` and `java_sdk_example/src/main/java/aws/sample/paymentcryptography/ServiceConstants.java`.
You can change the clear text Hex keys in order to import your own key.  If you do change the PEK or MAC keys in import app you will need to set the same values in `java_sdk_example/src/main/java/aws/sample/paymentcryptography/TerminalConstants.java` under "PEK" and "MAC_KEY_PLAIN_TEXT" variables.

If you change BDK key, you will need to generate corresponding DUKPT variants along with KSN using the BDK key and set those variants in the `java_sdk_example/src/main/java/aws/sample/paymentcryptography/p2pe/key-ksn-data.json` with corresponding KSN. Refer to https://github.com/SoftwareVerde/java-dukpt for information on DUKPT keys and variants. 

## Instructions
Either one of the approaches below can be used to import the keys. You will need AWS credentials to run the import app.

#### Using [Docker](https://docs.docker.com/get-docker/)
If you have Docker installed, you can run the commands below. This can be used if you do not have Python installed or do not want to import the Python libraries needed for this app in your local system.

```
cd samples-for-payment-cryptography-service/key-import-export

docker build -t key-import-app .

docker run  -e AWS_ACCESS_KEY_ID=<Access Key> -e AWS_SECRET_ACCESS_KEY=<SECRET KEY> -e AWS_DEFAULT_REGION=us-east-1 -it --rm key-import-app
```
Once you run the commands above, it will import the keys and create aliases for those keys in AWS Payment Cryptography. You can now run the JAVA samples which use these keys.

#### Using [Finch](https://github.com/runfinch/finch)
If you have Finch installed, you can run the commands below. This can be used if you do not have Python installed or do not want to import the Python libraries needed for this app in your local system.

```
cd samples-for-payment-cryptography-service/key-import-export

finch build -t key-import-app .

finch run  -e AWS_ACCESS_KEY_ID=<Access Key> -e AWS_SECRET_ACCESS_KEY=<SECRET KEY> -e AWS_DEFAULT_REGION=us-east-1 -it --rm key-import-app
```

Once you run the commands above, it will import the keys and create aliases for those keys in AWS Payment Cryptography. You can now run the JAVA samples which use these keys.


#### Using local Python to run the import app
```
cd samples-for-payment-cryptography-service/key-import-export/tr34/import_app

python -m venv .venv
source .venv/bin/activate 
python3 -m pip install psec boto3 pycryptodome
python3 apc_demo_keysetup.py

```

With either approaches, you should get an output like below -
```
*********Importing a KEK for importing subsequent keys*********

************************ DONE *****************
Imported Key: 79adaef3212aadce312ace422accfefb
Key Arn: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/3hn2ubebpeugbn22
Reported KCV: 3C0A31
Calculated KCV: 3C0A31
Reported Type: TDES_2KEY
KEK/KPBK/ZMK ARN: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/3hn2ubebpeugbn22

*********Importing TDES BDK for DUKPT*********

WRAPPED KEY IN TR-31 B0096B0TX00E0000A2C1AF40886230D79EAE236E54F22AA3617D8AF0ED7227872AAE1BA683917C48E530D9DA7F63B970
Imported Key: 8a8349794c9ee9a4c2927098f249fed6
Key Arn: arn:aws:payment-cryptography:us-west-2:XXXXXXXXXXXX:key/kiwl7juoitdeovx5
Reported KCV: 9C8552
Reported Type: TDES_2KEY
TDES BDK ARN: arn:aws:payment-cryptography:us-west-2:XXXXXXXXXXXX:key/kiwl7juoitdeovx5
Alias alias/MerchantTerminal_TDES_BDK

*********Importing AES BDK for DUKPT*********

WRAPPED KEY IN TR-31 B0112B0AX00E000033DFDAF93EBAE8FE476A2653A88DE4FF835C2114C97FEB2611A0D9A5F59988D3938C7E68597B3A07072C17A08ECF3B4D
Imported Key: 8a8349794c9ee9a4c2927098f249fed6
Key Arn: arn:aws:payment-cryptography:us-west-2:XXXXXXXXXXXX:key/u4lbzeh6onqscqjr
Reported KCV: B32CFD
Reported Type: AES_128
AES BDK ARN: arn:aws:payment-cryptography:us-west-2:XXXXXXXXXXXX:key/u4lbzeh6onqscqjr
Alias alias/MerchantTerminal_BDK_AES_128

*********Importing a PEK for communicating with ATM*********

WRAPPED KEY IN TR-31 B0096P0TB00E0000289A68560026472B58D327FAD108C28C0EF7672E2D7F21628BC201A89CC115F783738101301AC41B
Imported Key: 545e2aadfd5ec42f2f5be5e3adc75e9b290252a1a219b380
Key Arn: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/4lohwod3vn7u7fsq
Reported KCV: C15FFF
Reported Type: TDES_3KEY
PEK(ATM PEK) ARN: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/4lohwod3vn7u7fsq
Alias: alias/pinTranslateServicePek

*********Importing a PEK for Pin Translate Service to Issuer communication. This service sits between between issuer and ATM) *********

WRAPPED KEY IN TR-31 B0096P0TB00E0000A92C0E4FD9CCD3764829B749737406E4450251E6542D8BD916946AAB563A55E9936A8ED3D45E4FE9
Imported Key: 545e2aadfd5ec42f2f5be5e3adc75e9b290252a1a219b380
Key Arn: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/yq33o6suvqkr5wna
Reported KCV: C15FFF
Reported Type: TDES_3KEY
PEK(ATM PEK) ARN: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/yq33o6suvqkr5wna
Alias: alias/issuerPek

*********Generating a PGK for generating a PVV*********

Pin Verification Value ARN arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/bcpdzcpwgqkq6kbi
Pin Verification Value Alias alias/issuerPinValidationKey

*********Generating a MAC key for MAC verification********

************************ DONE *****************
Imported Key: 75bdaef54587cae6563a5ce57b4b9f9f
Key Arn: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/ryuqocdizyhkxgnt
Reported KCV: 946B22
Calculated KCV: 946B22
Reported Type: TDES_2KEY
MAC Key Alias: alias/tr31_macValidationKey
MAC Key ARN: arn:aws:payment-cryptography:us-east-1:XXXXXXXXXXXX:key/ryuqocdizyhkxgnt

*********Done*********
```
