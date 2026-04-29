# AWS Payment Cryptography Physical Key Exchange

The cloud formation stack template creates the necessary resources needed to perform a physical key exchange with AWS Payment Cryptography.

The template creates the following resources :
* S3 bucket for key exchange input and output - The inputs required for the key exchange and outputs from the key exchange will be shared using this bucket.
* ECC Key Pair in Payment Cryptography - This key pair will be used in the key exchange process using ECDH.
* Inputs Uploader lambda - This lambda will call the API GetPublicKeyCertificate for the key pair generated and uploads the PublicKeyCertificate and CertificateChain along with the KeyAttributes for the transport key into the S3 bucket shared with the Payment Cryptography service.

The template takes in the following parameters :
* BucketSuffix - The S3 bucket is required to be created with the suffix 'apc-physical-key-exchange'. You can add a random suffix to differentiate multiple buckets.
* KeyAlgorithm - KeyAlgorithm for the key to be transported. Only TDES and AES keys are supported for the exchange.
* KeyUsage - KeyUsage for the key to be transported. Only Base Derivation Key and Key Encryption Key are supported for the exchange.
* Exportable - Indicate whether the transport key should be exportable from the service or not.
* KeyModesOfUse - Key modes of use for the transport key. This should be valid for the KeyUsage selected for the transport key.

Example stack parameters input json.

```
[
  { 
    "ParameterKey": "BucketSuffix", 
    "ParameterValue": "<REPLACE WITH YOUR SUFFIX>"
  }, 
  { 
    "ParameterKey": "KeyAlgorithm",
    "ParameterValue": "<REPLACE WITH YOUR KEY ALGORITHM. Allowed values are TDES_2KEY, TDES_3KEY, AES_128, AES_192, AES_256.>"
  },
  {
    "ParameterKey": "KeyUsage",
    "ParameterValue": "<REPLACE WITH YOUR KEYUSAGE. Allowed values are TR31_B0_BASE_DERIVATION_KEY, TR31_K0_KEY_ENCRYPTION_KEY, TR31_K1_KEY_BLOCK_PROTECTION_KEY.>"
  },
  {
    "ParameterKey": "Exportable",
    "ParameterValue": "<Allowed values are true and false>"
  },
  {
    "ParameterKey": "KeyModesOfUse",
    "ParameterValue": "<REPLACE WITH YOUR KeyModesOfUse JSON string>"
  }
]
```

Create the cloudformation stack using the template file and stack parameters input.

```
aws cloudformation create-stack \
  --stack-name <STACK NAME> \
  --template-body file://physical-key-exchange-pre-requisites.yaml \
  --capabilities CAPABILITY_IAM \
  --region <REGION> \
  --parameters <STACK PARAMETERS INPUT FILE> 
```
