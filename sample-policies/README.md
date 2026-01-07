# Sample IAM Policies and SCPs
This folder contains samples of IAM Policies and Service Control Policies related to AWS Payment Cryptography.

## Sample Service Control Policies
1. [Lock AWS Payment Cryptogprahy so it's only used from VPC Endpoints (Prohibit direct internet access)](scp-vpc-endpoint.json)
1. [Lock down the management activities to a specific IAM Role](scp-lock-roles.json)
1. [Lock down the roles that are allowed to use AWS Payment Cryptography](scp-lock-management.json)

## Sample IAM Policies
1. [Sample Key Manager Operator Role](key-manager.json)

## Table guiding actions needed per use-case


| Service | Purpose | Allowed Actions | Notes |
| --- | ---| --- | --- |
| IssuerAuthorization| Processes Auths| VerifyAuthRequestCryptogram, VerifyPinData, VerifyCardData | Performs Main Card Validation Processes and Procedures |
| PaymentNetworkService| Handles connections to networks as it relates to cryptography such as Dynamic Key Exchange and generate/verifyMAC when networks require it.| Create Key, Export Key, GenerateMac, VerifyMac, GetParametersForExport| Limit key creation to payment-cryptography:KeyUsage = TR31_P0_PIN_ENCRYPTION_KEY.  Export can restrict based on tags (PURPOSE=NETWORK_DYNAMIC_KEYS) to prevent this role from exporting or using any other keys.  NOTE: Traditional HSM don’t have this level of granularity  |
| BinSetupProcessor| Creates New BINs. Create IAC template that creates key “bundle”. Tag keys with BIN to keep structured.| CreateKey,ExportKey, ImportKey, GetParametersForExport, GetParametersForImport| Create and Export key if this service is generating keys. ImportKey if this service is ingesting keys created elsewhere by a card issuance platform. |
| Processor| Execute Pinblock Translate operations and Generate/Verify MAC| TranslatePinData, GenerateMac, VerifyMac|  |
| Card Issuance| Can generate card printed values| GenerateCardValidationData, CreateKey, ExportKey, GetParametersForExport| Limit key usage creation with payment-cryptography:KeyUsage condition key |