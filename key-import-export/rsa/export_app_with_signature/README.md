# Automating Key Exchange with Trusted Business Partners

This solution sets up the necessary resources to assist you while exchanging keys with trusted business partners. It includes the following components:

- **AWS KMS Key**: An asymmetric KMS key (RSA 2048) is generated to create a cryptographic signature over a wrapped key encrypting key (KEK).
- **S3 Bucket**: An S3 bucket is created to store the outputs of the two Lambda functions, namely: ARNs of the generated keys, the encrypted KEK, the signature, and the key check value (KCV) of the KEK.
- **Lambda Functions**:
  - **CSRBuilderLambda**: This Lambda function generates a Certificate Signing Request (CSR) using the KMS key for signing. This Lambda is invoked automatically during the stack creation process, and outputs the CSR file to an S3 bucket. This function uses [the kms-csr-builder project.](https://github.com/aws-samples/csr-builder-for-kms)
  - **PspKEKexchangeLambda**: This Lambda function outputs the required information to initiate the key exchange process with your business partner: wrapped KEK, signature, and key check value (KCV) of KEK. More detail on the exact procedure can be found below.
- **Custom Resources**: Custom resources are used to trigger the CSRBuilderLambda function during the stack creation process, and create the Lambda layer used for both the deployed Lambda functions
- **IAM Roles and Policies**: Necessary IAM roles and policies are created to grant the required permissions to the Lambda functions.

## Background

In order for customers to begin encrypting and decrypting payment data between business partners, the initial step is to exchange a Key Encrypting Key (KEK).  This solution uses RSA-OAEP to wrap and securely export the KEK.

This solution can be used to combine AWS Payment Cryptography (APC) & AWS KMS to meet niche requirements for key exchange from specific business partners. There are two Lambda functions:

1. **CSRBuilderLambda** -- this function is used to create and sign a certificate signing request (CSR) using a specified AWS KMS asymmetric key (key usage: sign/verify). You can send this CSR to your business partner if needed to meet their key exchange requirements.
2. **PspKEKexchangeLambda** -- this function is used to wrap and export a KEK that is created in AWS Payment Cryptography. You can either let the Lambda function generate a new KEK, or specify the ARN for an existing KEK in AWS Payment Cryptography. To use this, you must provide the S3 URI that points to: a leaf certificate from your business partner (this will be used as the transport key to wrap the KEK), the intermediate or issuing CA certificate in the leaf certificate's chain of trust, and the root CA certificate in the leaf certificate's chain of trust. The full certificate chain, including these three certificates, should all be provided by your business partner.

The basic steps taken by the **PspKEKexchangeLambda** follow:

1. Ingests a leaf certificate from Amazon S3, and extracts the public key (sometimes referred to as transport key)
2. Performs certificate validations (check validity of cert, revocation status of cert, and checks for expected UIDs in cert)
3. Generates an AES128 key in APC (includes KCV [CMAC]), if one does not already exist
4. Uses transport key from step 1 to wrap and export AES128 key from AWS Payment Cryptography
5. Appends predefined headers to encrypted AES128 key, based on environment & data type values
6. Generates RSA keypair in AWS KMS (for signing), if one doesn't already exist. *Note:* If using the CloudFormation deployment, this KMS Key is pre-generated during stack creation.
7. Signs encrypted AES128 key + headers with RSA private key in AWS KMS
8. Returns encrypted key (without headers), signature computed over encrypted key (with headers), and KCV of AES128 key that was exported from AWS Payment Cryptography


## Deployment Instructions

**Prerequisites**: You need an AWS account with permissions to create and manage CloudFormation stacks.

**Upload the certificate and trust chain to Amazon S3**

1. First, you should upload the leaf certificate (containing the transport key for wrapping the KEK) to Amazon S3, and make note of the S3 URI. Ideally this S3 bucket is in the same account as the deployed functions, as this will make managing permissions easier. If your business partner provided the certificate as a single file with the entire trust chain, this will be the first certificate in the list.
2. Next, upload the corresponding issuing or intermediate certificate (ICA) to Amazon S3, and make note of the S3 URI. If your business partner provided the certificate as a single file with the entire trust chain, this will be the second certificate in the list.
3. Finally, upload the corresponding root certificate to Amazon S3, and make note of the S3 URI. If your business partner provided the certificate as a single file with the entire trust chain, this will be the last certificate in the list.

**Note** If your business partner provided the certificates as one file, copy each individual certificate into its own file (e.g., leafcert.pem, ica.pem, root.pem) and upload separately to S3. We will use these S3 URIs in the CloudFormation stack parameters and/or Lambda function environment variables.

**Deploy the CloudFormation Stack**:

1. Navigate to the CloudFormation console.
2. Click on "Create stack" and choose "With new resources (standard)".
3. Under "Prerequisite - Prepare template", select "Template is ready".
4. Download [this CloudFormation template](https://github.com/aws-samples/samples-for-payment-cryptography-service/tree/main/key-import-export/rsa/export_app_with_signature/cfn/template.yaml) to your local machine. 
5. Under "Specify template", select "Upload a template file" and choose the CloudFormation template file from your local machine.
6. Click "Next".
7. Enter a name for your stack in the "Stack name" field.
8. Provide values for the required parameters (see the "CloudFormation Stack Parameters" section below).

Required Parameters:

| Parameter | Description |
|------------|-------------|
| **COMMONNAME** | The common name for the certificate signing request generated by the CSRBuilderLambda (e.g., example.com). |
| **COUNTRYNAME** | The country name for the certificate signing request generated by the CSRBuilderLambda (e.g., US). |
| **LOCALITYNAME** | The locality name for the certificate signing request generated by the CSRBuilderLambda (e.g., San Francisco). |
| **ORGANIZATIONNAME** | The organization name for the certificate signing request generated by the CSRBuilderLambda (e.g., Example Organization). |
| **STATEORPROVINCENAME** | The state or province name for the certificate signing request generated by the CSRBuilderLambda (e.g., California). |
| **Environment** | The environment for the key exchange process (non-production or production). This value is used to determine which UIDs should be verified in the leaf certificate. Your business partner should provide information about which environment value to use. |
| **DataType** | The data type for the key exchange process (cardholder or pin). This value is used to determine which UIDs should be verified in the leaf certificate. Your business partner should provide information about which data type value to use. |
| **CertificateS3URI** | The S3 URI for the leaf certificate (transport key) provided by your business partner (e.g., s3://bucket-name/path/to/certificate.pem). This should be the location where you uploaded the leaf certificate / end-entity certificate provided by your business partner. The PspKEKExchangeLambda will extract the public key from this certificate, and use it to wrap the KEK. |
| **RootCertificateS3URI** | The S3 URI for the root certificate associated with the transport key (e.g., s3://bucket-name/path/to/root-certificate.pem). The PspKEKExchangeLambda will import this certificate to AWS Payment Cryptography, as this is required to wrap and export the KEK using the transport key.|
| **ICACertificateS3URI** | The S3 URI for the intermediate or issuing CA certificate associated with the transport key (e.g., s3://bucket-name/path/to/ica-certificate.pem). The PspKEKExchangeLambda will import this certificate to AWS Payment Cryptography, as this is required to wrap and export the KEK using the transport key. |

Optional Parameters:

| Parameter | Description |
|------------|-------------|
| **APCRootKeyARN** | The ARN of a root certificate that you have previously imported to AWS Payment Cryptography. Use this parameter if you have already imported the Root CA certificate into APC. You can modify this as an environment variable in the PspKEKExchangeLambda function after stack creation completes, if you choose. If this value is empty, the PspKEKExchangeLambda will import the certificate using the value specified in the **RootCertificateS3URI** parameter. |
| **APCICAKeyARN** | The ARN of a intermediate or issuing certificate that you have previously imported to AWS Payment Cryptography. Use this parameter if you have already imported the ICA certificate into APC. You can modify this as an environment variable in the PspKEKExchangeLambda function after stack creation completes, if you choose. If this value is empty, the PspKEKExchangeLambda will import the certificate using the value specified in the **ICACertificateS3URI** parameter. |
| **APCKeyARN** | The ARN of the KEK you want to securely export and exchange with your trusted business partner. Use this parameter if you have already generated or imported your KEK in AWS Payment Cryptography. You can modify this as an environment variable in the PspKEKExchangeLambda function after stack creation completes, if you choose. If this value is empty, the PspKEKExchangeLambda will generate a new AES128 KEK in AWS Payment Cryptography on your behalf. |

9. Click "Next".
10. Check the box for "CAPABILITY_NAMED_IAM" since this stack creates IAM roles and policies.
11. Click "Create stack".

The stack creation process takes around 5-10 minutes. 

## Access the Results of the Stack Creation
After the stack creation is complete, you can view the created resources in the "Resources" tab of your CloudFormation stack; and you can view the CSR generated by the CSRBuilderLambda function in the S3 bucket specified by the `ResultsBucket` output on the "Outputs" tab of your CloudFormation stack.

## Invoke the PspKEKExchangeLambda function

Follow [the instructions in the AWS documentation](https://docs.aws.amazon.com/lambda/latest/dg/lambda-invocation.html) to invoke the PspKEKExchangeLambda function using your preferred method. For example, using the AWS CLI:

```

aws lambda invoke \
    --cli-binary-format raw-in-base64-out \
    --function-name INSERT-PSP-KEK-EXCHANGE-LAMBDA-FUNCTION-NAME \
    --cli-binary-format raw-in-base64-out \
    --payload '{ "Test": "Example" }' \
    response.json

```

You can then view the response in the response.json file output:

```

cat response.json

```

Alternatively, you can invoke the PSPKEKExchange Lambda function via the AWS Lambda console, by selecting the function, and under the **Test** column, select 'Test'. 

***Note*** The event payload passed the Lambda function does not matter in this case, as the environment variables are used instead. Therefore when invoking the Lambda, the payload can be ignored/configured as you wish without any impact to the output of the function.

### Error Handling

The PspKEKExchangeLambda function includes error handling and logging. In case of an error, it returns a 500 status code with detailed error information.

### Output

The PspKEKExchangeLambda function returns a JSON response with:
- Status code
- Message
- Result object containing:
  - Key ARNs
  - Encrypted AES key
  - Key Check Value (KCV)
  - Digital signature
  - S3 storage locations (if applicable)
  
The results will also be stored in S3 as files.

### Dependencies

- boto3
- requests
- cryptography
- asn1crypto
- oscrypto

### Usage

 Ensure all environment variables are correctly set before invoking the function. If using the CloudFormation stack deployment, the environment variables will be pre-populated based on your stack parameters. Environment variables for PspKEKExchangeLambda function can be found below:

Required Parameters:

| Parameter | Description |
|------------|-------------|
| **Environment** | The environment for the key exchange process (non-production or production). This value is used to determine which UIDs should be verified in the leaf certificate. Your business partner should provide information about which environment value to use. |
| **DataType** | The data type for the key exchange process (cardholder or pin). This value is used to determine which UIDs should be verified in the leaf certificate. Your business partner should provide information about which data type value to use. |
| **CertificateS3URI** | The S3 URI for the leaf certificate (transport key) provided by your business partner (e.g., s3://bucket-name/path/to/certificate.pem). This should be the location where you uploaded the leaf certificate / end-entity certificate provided by your business partner. The PspKEKExchangeLambda will extract the public key from this certificate, and use it to wrap the KEK. |
| **RootCertificateS3URI** | The S3 URI for the root certificate associated with the transport key (e.g., s3://bucket-name/path/to/root-certificate.pem). The PspKEKExchangeLambda will import this certificate to AWS Payment Cryptography, as this is required to wrap and export the KEK using the transport key.|
| **ICACertificateS3URI** | The S3 URI for the intermediate or issuing CA certificate associated with the transport key (e.g., s3://bucket-name/path/to/ica-certificate.pem). The PspKEKExchangeLambda will import this certificate to AWS Payment Cryptography, as this is required to wrap and export the KEK using the transport key. |

Optional Parameters:

| Parameter | Description |
|------------|-------------|
| **APCRootKeyARN** | The ARN of a root certificate that you have previously imported to AWS Payment Cryptography. Use this parameter if you have already imported the Root CA certificate into APC. If this value is empty, the PspKEKExchangeLambda will import the certificate using the value specified in the **RootCertificateS3URI** parameter. |
| **APCICAKeyARN** | The ARN of a intermediate or issuing certificate that you have previously imported to AWS Payment Cryptography. Use this parameter if you have already imported the ICA certificate into APC. If this value is empty, the PspKEKExchangeLambda will import the certificate using the value specified in the **ICACertificateS3URI** parameter. |
| **APCKeyARN** | The ARN of the KEK you want to securely export and exchange with your trusted business partner. Use this parameter if you have already generated or imported your KEK in AWS Payment Cryptography. If this value is empty, the PspKEKExchangeLambda will generate a new AES128 KEK in AWS Payment Cryptography on your behalf. |

### Security Considerations

- Ensure proper IAM permissions are set for accessing S3, KMS, and Payment Cryptography services
- Keep all ARNs and sensitive data secure
- Regularly rotate keys and review access policies for least-privilege access principle

### Maintenance

Regularly update the Python runtime and dependencies to ensure security and compatibility with AWS services.

